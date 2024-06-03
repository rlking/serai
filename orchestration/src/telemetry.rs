use std::path::Path;
use crate::{get_serai_pub_key, Network, write_dockerfile};

pub fn setup_fluentbit(orchestration_path: &Path, network: Network, host: &str) {
    let validator_pub_key = get_serai_pub_key(network).unwrap();

    let config = format!(r#"
[SERVICE]
    Flush        1
    Log_Level    info

[INPUT]
    Name              forward
    Listen            0.0.0.0
    Port              24224

[OUTPUT]
    Name http
    Match *
    Host {host}
    Port 21892
    URI /log/ingest
    Format json
    tls  On

[FILTER]
    Name        record_modifier
    Match       *
    Record      validator {validator_pub_key}

[FILTER]
    Name        record_modifier
    Match       *
    Record      network {}
"#,
                         network.label(),
    );

    let mut fluentbit_path = orchestration_path.to_path_buf();
    fluentbit_path.push("fluentbit");

    let config_path = fluentbit_path.join("fluent-bit.conf");
    write_dockerfile(config_path, &config);

    let dockerfile = format!(r#"
FROM fluent/fluent-bit

ADD /orchestration/{}/fluentbit/fluent-bit.conf /fluent-bit/etc/fluent-bit.conf

EXPOSE 24224/tcp
EXPOSE 24224/udp
"#
                             , network.label());

    let dockerfile_path = fluentbit_path.join("Dockerfile");
    write_dockerfile(dockerfile_path, &dockerfile);
}