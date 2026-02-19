//! Native WS-Management (WinRM) implementation for Linux/macOS.
//!
//! Uses ntlmclient for NTLM auth and reqwest for HTTP. Implements the
//! WS-Management protocol: Create shell, Execute, Receive, Delete.

use crate::exec::{ExecCredentials, ExecMethod, ExecOutput, RemoteExecutor};
use crate::error::{OverthroneError, Result};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ntlmclient::{respond_challenge_ntlm_v2, Credentials, Flags, get_ntlm_time, Message};
use quick_xml::events::Event;
use quick_xml::Reader;
use reqwest::Client;
use tracing::{debug, info};
use uuid::Uuid;

const SHELL_URI: &str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd";
const CREATE_ACTION: &str = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create";
const CREATE_RESPONSE_ACTION: &str = "http://schemas.xmlsoap.org/ws/2004/09/transfer/CreateResponse";
const SEND_ACTION: &str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send";
const RECEIVE_ACTION: &str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive";
const RECEIVE_RESPONSE_ACTION: &str =
    "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/ReceiveResponse";
const SIGNAL_ACTION: &str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal";
const DELETE_ACTION: &str = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete";

pub struct WinRmExecutor {
    pub(super) creds: ExecCredentials,
    pub(super) use_ssl: bool,
    pub(super) port: u16,
}

impl WinRmExecutor {
    pub fn new(creds: ExecCredentials) -> Self {
        Self {
            creds,
            use_ssl: true,
            port: 5986,
        }
    }

    pub fn with_http(mut self) -> Self {
        self.use_ssl = false;
        self.port = 5985;
        self
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    fn build_url(&self, target: &str) -> String {
        let scheme = if self.use_ssl { "https" } else { "http" };
        format!("{scheme}://{target}:{}/wsman", self.port)
    }

    fn build_client(&self) -> Result<Client> {
        let mut builder = Client::builder().cookie_store(true);
        if self.use_ssl {
            builder = builder.danger_accept_invalid_certs(true);
        }
        builder
            .build()
            .map_err(|e| OverthroneError::Exec(format!("reqwest client: {e}")))
    }

    /// Perform NTLM-authenticated request. Handles Type1/Type2/Type3 exchange.
    async fn ntlm_request(
        &self,
        client: &Client,
        url: &str,
        body: &str,
        content_type: &str,
    ) -> Result<(reqwest::Response, bool)> {
        let nego_flags = Flags::NEGOTIATE_UNICODE
            | Flags::REQUEST_TARGET
            | Flags::NEGOTIATE_NTLM
            | Flags::NEGOTIATE_WORKSTATION_SUPPLIED;
        let nego_msg = ntlmclient::Message::Negotiate(ntlmclient::NegotiateMessage {
            flags: nego_flags,
            supplied_domain: String::new(),
            supplied_workstation: "WORKSTATION".to_string(),
            os_version: Default::default(),
        });
        let nego_bytes = nego_msg.to_bytes().map_err(|e| {
            OverthroneError::Exec(format!("NTLM negotiate encode: {e:?}"))
        })?;
        let nego_b64 = BASE64.encode(&nego_bytes);

        let resp = client
            .post(url)
            .header("Content-Type", content_type)
            .header("Authorization", format!("NTLM {}", nego_b64))
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| OverthroneError::Exec(format!("HTTP request: {e}")))?;

        let status = resp.status();
        let auth_header = resp.headers().get("www-authenticate");
        let challenge_b64 = match auth_header {
            Some(h) => {
                let s = h.to_str().map_err(|_| {
                    OverthroneError::Exec("Invalid www-authenticate header".into())
                })?;
                s.strip_prefix("NTLM ")
                    .or_else(|| s.split_whitespace().nth(1))
                    .ok_or_else(|| OverthroneError::Exec("No NTLM challenge in response".into()))?
            }
            None => {
                if status.is_success() {
                    return Ok((resp, true));
                }
                return Err(OverthroneError::Exec(format!(
                    "WinRM request failed: {} (no NTLM challenge)",
                    status
                )));
            }
        };

        let challenge_bytes = BASE64.decode(challenge_b64).map_err(|e| {
            OverthroneError::Exec(format!("NTLM challenge decode: {e}"))
        })?;
        let challenge_msg = Message::try_from(challenge_bytes.as_slice())
            .map_err(|e| OverthroneError::Exec(format!("NTLM challenge parse: {e:?}")))?;
        let challenge = match challenge_msg {
            Message::Challenge(c) => c,
            _ => return Err(OverthroneError::Exec("Expected NTLM challenge".into())),
        };

        let target_info: Vec<u8> = challenge.target_information.iter().flat_map(|ie| ie.to_bytes()).collect();
        let creds = Credentials {
            username: self.creds.username.clone(),
            password: self.creds.password.clone(),
            domain: self.creds.domain.clone(),
        };
        let challenge_response = respond_challenge_ntlm_v2(
            challenge.challenge,
            &target_info,
            get_ntlm_time(),
            &creds,
        );
        let auth_flags = Flags::NEGOTIATE_UNICODE | Flags::NEGOTIATE_NTLM;
        let auth_msg = challenge_response.to_message(&creds, "WORKSTATION", auth_flags);
        let auth_bytes = auth_msg.to_bytes().map_err(|e| {
            OverthroneError::Exec(format!("NTLM auth encode: {e:?}"))
        })?;
        let auth_b64 = BASE64.encode(&auth_bytes);

        let resp2 = client
            .post(url)
            .header("Content-Type", content_type)
            .header("Authorization", format!("NTLM {}", auth_b64))
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| OverthroneError::Exec(format!("HTTP auth request: {e}")))?;

        Ok((resp2, resp2.status().is_success()))
    }

    fn make_envelope(&self, target: &str, action: &str, body: &str, shell_id: Option<&str>) -> String {
        let message_id = Uuid::new_v4();
        let url = self.build_url(target);
        let shell_selector = shell_id.map_or_else(String::new, |id| {
            format!(
                r#"<wsman:SelectorSet><wsman:Selector Name="ShellId">{}</wsman:Selector></wsman:SelectorSet>"#,
                id
            )
        });
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
  <s:Header>
    <wsa:To>{url}</wsa:To>
    <wsman:ResourceURI s:mustUnderstand="true">{shell_uri}</wsman:ResourceURI>
    <wsa:ReplyTo><wsa:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address></wsa:ReplyTo>
    <wsa:Action s:mustUnderstand="true">{action}</wsa:Action>
    <wsman:MaxEnvelopeSize s:mustUnderstand="true">153600</wsman:MaxEnvelopeSize>
    <wsa:MessageID>uuid:{message_id}</wsa:MessageID>
    <wsman:Locale xml:lang="en-US" s:mustUnderstand="false"/>
    <wsman:OptionSet>
      <wsman:Option Name="WINRS_NOPROFILE">TRUE</wsman:Option>
      <wsman:Option Name="WINRS_CODEPAGE">437</wsman:Option>
    </wsman:OptionSet>
    <wsman:OperationTimeout>PT60S</wsman:OperationTimeout>
    {shell_selector}
  </s:Header>
  <s:Body>
    {body}
  </s:Body>
</s:Envelope>"#,
            url = url,
            shell_uri = SHELL_URI,
            action = action,
            message_id = message_id,
            shell_selector = shell_selector,
            body = body
        )
    }

    fn create_shell_body() -> String {
        r#"<rsp:Shell xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
  <rsp:InputStreams>stdin</rsp:InputStreams>
  <rsp:OutputStreams>stdout stderr</rsp:OutputStreams>
</rsp:Shell>"#
            .to_string()
    }

    fn command_body(command: &str) -> String {
        let escaped = command
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;");
        format!(
            r#"<rsp:CommandLine xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
  <rsp:Command>{}</rsp:Command>
</rsp:CommandLine>"#,
            escaped
        )
    }

    fn receive_body(streams: &str) -> String {
        format!(
            r#"<rsp:Receive xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
  <rsp:DesiredStream>{}</rsp:DesiredStream>
</rsp:Receive>"#,
            streams
        )
    }

    fn extract_shell_id(xml: &str) -> Result<String> {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);
        let mut buf = Vec::new();
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    if e.name().as_ref() == b"wsman:Selector"
                        || e.name().as_ref() == b"Selector"
                    {
                        let mut is_shell_id = false;
                        for a in e.attributes() {
                            if let Ok(attr) = a {
                                if attr.key.as_ref() == b"Name"
                                    && attr.value.as_ref() == b"ShellId"
                                {
                                    is_shell_id = true;
                                    break;
                                }
                            }
                        }
                        if is_shell_id {
                            buf.clear();
                            match reader.read_event_into(&mut buf) {
                                Ok(Event::Text(t)) => {
                                    return Ok(t
                                        .unescape()
                                        .unwrap_or_default()
                                        .trim()
                                        .to_string());
                                }
                                _ => {}
                            }
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => return Err(OverthroneError::Exec(format!("XML parse: {e}"))),
                _ => {}
            }
            buf.clear();
        }
        Err(OverthroneError::Exec("ShellId not found in Create response".into()))
    }

    fn extract_stream_output(xml: &str, stream: &str) -> (String, Option<i32>) {
        let mut stdout = String::new();
        let mut exit_code: Option<i32> = None;
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);
        let mut buf = Vec::new();
        let stream_attr = format!("rsp:{}", stream);
        let stream_bytes = stream_attr.as_bytes();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                    let name = e.name().as_ref();
                    if name == b"rsp:Stream" || name == b"Stream" {
                        for a in e.attributes() {
                            if let Ok(attr) = a {
                                let key = attr.key.as_ref();
                                let val = attr.value.as_ref();
                                if key == b"Name" && val == stream.as_bytes() {
                                    if let Ok(Event::Text(t)) = reader.read_event_into(&mut buf) {
                                        let unescaped = t.unescape().unwrap_or_default();
                                        if let Ok(decoded) = BASE64.decode(unescaped.trim()) {
                                            stdout.push_str(
                                                &String::from_utf8_lossy(&decoded).to_string(),
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    } else if name == b"rsp:ExitCode" || name == b"ExitCode" {
                        if let Ok(Event::Text(t)) = reader.read_event_into(&mut buf) {
                            if let Ok(n) = t.unescape().unwrap_or_default().trim().parse::<i32>() {
                                exit_code = Some(n);
                            }
                        }
                    }
                }
                Ok(Event::Eof) => break,
                _ => {}
            }
            buf.clear();
        }
        (stdout, exit_code)
    }

    async fn execute_wsman(&self, target: &str, command: &str) -> Result<ExecOutput> {
        let url = self.build_url(target);
        let client = self.build_client()?;

        let create_body = Self::create_shell_body();
        let create_envelope = self.make_envelope(target, CREATE_ACTION, &create_body, None);

        let (resp, _) = self
            .ntlm_request(
                &client,
                &url,
                &create_envelope,
                "application/soap+xml;charset=UTF-8",
            )
            .await?;

        let status = resp.status();
        let create_xml = resp.text().await.map_err(|e| {
            OverthroneError::Exec(format!("Create response read: {e}"))
        })?;

        if !status.is_success() {
            return Err(OverthroneError::Exec(format!(
                "WinRM Create failed: {} - {}",
                status,
                create_xml.chars().take(500).collect::<String>()
            )));
        }

        let shell_id = Self::extract_shell_id(&create_xml)?;
        debug!("WinRM shell created: {}", shell_id);

        let cmd_body = Self::command_body(command);
        let send_envelope = self.make_envelope(target, SEND_ACTION, &cmd_body, Some(&shell_id));

        let (send_resp, _) = self
            .ntlm_request(
                &client,
                &url,
                &send_envelope,
                "application/soap+xml;charset=UTF-8",
            )
            .await?;

        if !send_resp.status().is_success() {
            return Err(OverthroneError::Exec("WinRM Send/Execute failed".into()));
        }

        let receive_body = Self::receive_body("stdout stderr");
        let receive_envelope = self.make_envelope(target, RECEIVE_ACTION, &receive_body, Some(&shell_id));

        let (recv_resp, _) = self
            .ntlm_request(
                &client,
                &url,
                &receive_envelope,
                "application/soap+xml;charset=UTF-8",
            )
            .await?;

        let recv_xml = recv_resp.text().await.map_err(|e| {
            OverthroneError::Exec(format!("Receive response read: {e}"))
        })?;

        let (stdout, _) = Self::extract_stream_output(&recv_xml, "stdout");
        let (stderr, exit_code) = Self::extract_stream_output(&recv_xml, "stderr");
        let (_, exit_from_stdout) = Self::extract_stream_output(&recv_xml, "stdout");
        let exit_code = exit_code.or(exit_from_stdout);

        let delete_body = "";
        let delete_envelope = self.make_envelope(target, DELETE_ACTION, delete_body, Some(&shell_id));
        let _ = self
            .ntlm_request(
                &client,
                &url,
                &delete_envelope,
                "application/soap+xml;charset=UTF-8",
            )
            .await;

        Ok(ExecOutput {
            stdout,
            stderr,
            exit_code,
            method: ExecMethod::WinRM,
        })
    }
}

#[async_trait]
impl RemoteExecutor for WinRmExecutor {
    fn method(&self) -> ExecMethod {
        ExecMethod::WinRM
    }

    async fn execute(&self, target: &str, command: &str) -> Result<ExecOutput> {
        info!("WinRM: Executing on {target}: {command} (WS-Man)");
        self.execute_wsman(target, command).await
    }

    async fn check_available(&self, target: &str) -> bool {
        let url = self.build_url(target);
        let client = match self.build_client() {
            Ok(c) => c,
            Err(_) => return false,
        };
        let create_body = Self::create_shell_body();
        let create_envelope = self.make_envelope(target, CREATE_ACTION, &create_body, None);
        match self
            .ntlm_request(
                &client,
                &url,
                &create_envelope,
                "application/soap+xml;charset=UTF-8",
            )
            .await
        {
            Ok((resp, _)) => {
                if resp.status().is_success() {
                    if let Ok(text) = resp.text().await {
                        if let Ok(shell_id) = Self::extract_shell_id(&text) {
                            let delete_body = "";
                            let delete_envelope =
                                self.make_envelope(target, DELETE_ACTION, delete_body, Some(&shell_id));
                            let _ = self
                                .ntlm_request(
                                    &client,
                                    &url,
                                    &delete_envelope,
                                    "application/soap+xml;charset=UTF-8",
                                )
                                .await;
                        }
                    }
                    return true;
                }
            }
            Err(_) => {}
        }
        false
    }
}

impl Clone for WinRmExecutor {
    fn clone(&self) -> Self {
        Self {
            creds: self.creds.clone(),
            use_ssl: self.use_ssl,
            port: self.port,
        }
    }
}
