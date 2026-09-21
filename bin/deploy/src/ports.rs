use std::collections::{BTreeMap, btree_map::Entry};

/// Port assignments that must remain distinct.
#[derive(Default)]
pub(crate) struct Ports {
    services: BTreeMap<u16, String>,
}

impl Ports {
    pub(crate) fn insert(&mut self, service: impl Into<String>, port: u16) -> Result<(), String> {
        let service = service.into();
        if port == 0 {
            return Err(format!("{service} requires a fixed nonzero port"));
        }

        match self.services.entry(port) {
            Entry::Occupied(entry) => Err(format!(
                "port {port} collision between {} and {service}",
                entry.get()
            )),
            Entry::Vacant(entry) => {
                entry.insert(service);
                Ok(())
            }
        }
    }

    pub(crate) fn insert_range(
        &mut self,
        service: &str,
        base: u16,
        count: u32,
    ) -> Result<(), String> {
        let Some(last) = count.checked_sub(1) else {
            return Ok(());
        };

        let last = u16::try_from(last)
            .ok()
            .and_then(|offset| base.checked_add(offset))
            .ok_or_else(|| format!("{service} port range overflow"))?;
        for (index, port) in (base..=last).enumerate() {
            self.insert(format!("{service} {index}"), port)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{Cli, Command, GenerateTarget, local};
    use clap::Parser;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn indexer_metrics_collision_fails_before_writing_bundle() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let output_dir = std::env::temp_dir().join(format!(
            "constantinople-port-collision-{}-{suffix}",
            std::process::id()
        ));
        let cli = Cli::try_parse_from([
            "constantinople-deploy",
            "generate",
            "--validators",
            "4",
            "--indexer",
            "--output-dir",
            output_dir.to_str().expect("UTF-8 output path"),
            "local",
            "--base-metrics-port",
            "8085",
        ])
        .expect("parse deploy arguments");
        let Command::Generate(args) = cli.command else {
            panic!("expected generate command");
        };
        let GenerateTarget::Local(local_args) = &args.target else {
            panic!("expected local target");
        };
        let message =
            local::generate(&args, local_args).expect_err("port collision must reject the bundle");

        assert!(
            message.contains(
                "port 8090 collision between chain-indexer Store and chain-indexer metrics"
            ),
            "{message}"
        );
        assert!(
            !output_dir.exists(),
            "invalid ports must not leave a bundle"
        );
    }
}
