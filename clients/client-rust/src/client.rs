use crate::Credentials;
use async_std::task;
use backoff::backoff::Backoff;
use backoff::ExponentialBackoff;
use failure::{format_err, Error, ResultExt};
use hawk;
use reqwest;
use reqwest::header::HeaderValue;
use std::borrow::Borrow;
use std::iter::IntoIterator;
use std::str::FromStr;
use std::time::Duration;

/// A shortcut for None to indicate no body is being supplied for a request.
pub const NO_BODY: Option<&str> = None;

/// A shortcut for None to indicate that no query is being supplied for a request
pub const NO_QUERY: Option<Vec<(String, String)>> = None;

/// Client is the entry point into all the functionality in this package. It
/// contains authentication credentials, and a service endpoint, which are
/// required for all HTTP operations.
#[derive(Debug, Clone)]
pub struct Client {
    /// The credentials associated with this client and used for requests.
    /// If None, then unauthenticated requests are made.
    pub credentials: Option<Credentials>,
    /// The root URL for the Taskcluster deployment
    root_url: reqwest::Url,
    /// Reqwest client
    client: reqwest::Client,
}

impl Client {
    /// Instatiate a new client for a taskcluster service.
    /// The root_url is the taskcluster deployment root url,
    /// service_name is the name of the service and version
    /// is the service version
    pub fn new<'b>(
        root_url: &str,
        service_name: &str,
        version: &str,
        credentials: Option<Credentials>,
    ) -> Result<Client, Error> {
        Ok(Client {
            credentials,
            root_url: reqwest::Url::parse(root_url)
                .context(root_url.to_owned())?
                .join(&format!("/{}/{}/", service_name, version))
                .context(format!("{} {}", service_name, version))?,
            client: reqwest::Client::new(),
        })
    }

    /// request is the underlying method that makes a raw API request,
    /// performing any json marshaling/unmarshaling of requests/responses.
    pub async fn request<'a, I, K, V, B>(
        &self,
        method: &str,
        path: &str,
        query: Option<I>,
        body: Option<B>,
    ) -> Result<reqwest::Response, Error>
    where
        I: IntoIterator,
        I::Item: Borrow<(K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
        B: serde::Serialize,
    {
        let mut backoff = ExponentialBackoff::default();
        backoff.max_elapsed_time = Some(Duration::from_secs(5));
        backoff.reset();

        let req = self.build_request(method, path, query, body)?;
        let url = req.url().as_str();

        let resp = loop {
            let req = req
                .try_clone()
                .ok_or(format_err!("Cannot clone the request {}", url))?;

            let result = self.exec_request(url, method, req).await;
            if result.is_ok() {
                break result;
            }

            match backoff.next_backoff() {
                Some(duration) => task::sleep(duration).await,
                None => break result,
            }
        }?;

        let status = resp.status();
        if status.is_success() {
            Ok(resp)
        } else {
            Err(format_err!(
                "Error executing request\nmethod: {}\nurl: {}\nstatus: {}({})\nresponse: \"{}\"",
                method,
                &url,
                status.canonical_reason().unwrap_or("Unknown error"),
                status.as_str(),
                resp.text()
                    .await
                    .unwrap_or_else(|err| format!("Cannot retrieve response body: {}", err)),
            ))
        }
    }

    async fn exec_request(
        &self,
        url: &str,
        method: &str,
        req: reqwest::Request,
    ) -> Result<reqwest::Response, Error> {
        let resp = self.client.execute(req).await.context(url.to_owned())?;

        let status = resp.status();
        if status.is_server_error() {
            Err(format_err!(
                "Error executing request\nmethod: {}\nrequest\nURL: {}\nstatus: {}({})\nresponse: \"{}\"",
                method,
                url,
                status.canonical_reason().unwrap_or("Unknown error"),
                status.as_str(),
                resp.text()
                    .await
                    .unwrap_or_else(|err| format!("Cannot retrieve response body: {}", err)),
            ))
        } else {
            Ok(resp)
        }
    }

    fn build_request<'b, I, K, V, B>(
        &self,
        method: &str,
        path: &str,
        query: Option<I>,
        body: Option<B>,
    ) -> Result<reqwest::Request, Error>
    where
        I: IntoIterator,
        I::Item: Borrow<(K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
        B: serde::Serialize,
    {
        let mut url = self.root_url.join(path).context(path.to_owned())?;

        if let Some(q) = query {
            url.query_pairs_mut().extend_pairs(q);
        }

        let meth = reqwest::Method::from_str(method).context(method.to_owned())?;

        let req = self.client.request(meth, url);

        let req = match body {
            Some(b) => req.json(&b),
            None => req,
        };

        let req = req
            .build()
            .context(method.to_owned())
            .context(path.to_owned())?;

        match self.credentials {
            Some(ref c) => {
                let creds = hawk::Credentials {
                    id: c.client_id.clone(),
                    key: hawk::Key::new(&c.access_token, hawk::SHA256)
                        .context(c.client_id.to_owned())?,
                };

                self.sign_request(&creds, req)
            }
            None => Ok(req),
        }
    }

    fn sign_request(
        &self,
        creds: &hawk::Credentials,
        req: reqwest::Request,
    ) -> Result<reqwest::Request, Error> {
        let host = req.url().host_str().ok_or(format_err!(
            "The root URL {} doesn't contain a host",
            req.url(),
        ))?;

        let port = req.url().port_or_known_default().ok_or(format_err!(
            "Unkown port for protocol {}",
            self.root_url.scheme()
        ))?;

        let signed_req_builder =
            hawk::RequestBuilder::new(req.method().as_str(), host, port, req.url().path());

        let payload_hash;
        let signed_req_builder = match req.body() {
            Some(ref b) => {
                let b = b.as_bytes().ok_or(format_err!("Body is a stream???"))?;
                payload_hash = hawk::PayloadHasher::hash("text/json", hawk::SHA256, b)?;
                signed_req_builder.hash(&payload_hash[..])
            }
            None => signed_req_builder,
        };

        let header = signed_req_builder.request().make_header(&creds)?;

        let token = HeaderValue::from_str(format!("Hawk {}", header).as_str()).context(header)?;

        let mut req = req;
        req.headers_mut().insert("Authorization", token);
        Ok(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::AUTHORIZATION;
    use httptest::{matchers::*, responders::*, Expectation, Server};
    use serde_json::json;
    use std::fmt;
    use std::net::SocketAddr;
    use tokio;

    #[tokio::test]
    async fn test_simple_request() -> Result<(), Error> {
        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/queue/v1/ping"))
                .respond_with(status_code(200)),
        );
        let root_url = format!("http://{}", server.addr());

        let client = Client::new(&root_url, "queue", "v1", None)?;
        let resp = client.request("GET", "ping", NO_QUERY, NO_BODY).await?;
        assert!(resp.status().is_success());
        Ok(())
    }

    /// An httptest matcher that will check Hawk authentication with the given cedentials.
    pub fn signed_with(creds: Credentials, addr: SocketAddr) -> SignedWith {
        SignedWith(creds, addr)
    }

    #[derive(Debug)]
    pub struct SignedWith(Credentials, SocketAddr);

    impl<B> Matcher<http::Request<B>> for SignedWith {
        fn matches(&mut self, input: &http::Request<B>, _ctx: &mut ExecutionContext) -> bool {
            let auth_header = input.headers().get(AUTHORIZATION).unwrap();
            let auth_header = auth_header.to_str().unwrap();
            if !auth_header.starts_with("Hawk ") {
                println!("Authorization header does not start with Hawk");
                return false;
            }
            let auth_header: hawk::Header = auth_header[5..].parse().unwrap();

            let host = format!("{}", self.1.ip());
            let hawk_req = hawk::RequestBuilder::new(
                input.method().as_str(),
                &host,
                self.1.port(),
                input.uri().path(),
            )
            .request();

            let key = hawk::Key::new(&self.0.access_token, hawk::SHA256).unwrap();

            if !hawk_req.validate_header(&auth_header, &key, std::time::Duration::from_secs(1)) {
                println!("Validation failed");
                return false;
            }

            true
        }

        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            <Self as fmt::Debug>::fmt(self, f)
        }
    }

    #[tokio::test]
    async fn test_simple_request_with_perm_creds() -> Result<(), Error> {
        let creds = Credentials::new("clientId", "accessToken");

        let server = Server::run();
        server.expect(
            Expectation::matching(all_of![
                request::method_path("GET", "/queue/v1/ping"),
                signed_with(creds.clone(), server.addr()),
            ])
            .respond_with(status_code(200)),
        );
        let root_url = format!("http://{}", server.addr());

        let client = Client::new(&root_url, "queue", "v1", Some(creds))?;
        let resp = client.request("GET", "ping", NO_QUERY, NO_BODY).await?;
        assert!(resp.status().is_success());
        Ok(())
    }

    #[tokio::test]
    async fn test_query() -> Result<(), Error> {
        let server = Server::run();
        server.expect(
            Expectation::matching(all_of![
                request::method_path("GET", "/queue/v1/test"),
                request::query(url_decoded(contains(("taskcluster", "test")))),
                request::query(url_decoded(contains(("client", "rust")))),
            ])
            .respond_with(status_code(200)),
        );
        let root_url = format!("http://{}", server.addr());

        let client = Client::new(&root_url, "queue", "v1", None)?;
        let resp = client
            .request(
                "GET",
                "test",
                Some(&[("taskcluster", "test"), ("client", "rust")]),
                NO_BODY,
            )
            .await?;
        assert!(resp.status().is_success());
        Ok(())
    }

    #[tokio::test]
    async fn test_body() -> Result<(), Error> {
        let body = json!({"hello": "world"});

        let server = Server::run();
        server.expect(
            Expectation::matching(all_of![
                request::method_path("POST", "/queue/v1/test"),
                request::body(json_decoded(eq(body.clone()))),
            ])
            .respond_with(status_code(200)),
        );
        let root_url = format!("http://{}", server.addr());

        let client = Client::new(&root_url, "queue", "v1", None)?;
        let resp = client.request("POST", "test", NO_QUERY, Some(body)).await?;
        assert!(resp.status().is_success());
        Ok(())
    }
}
