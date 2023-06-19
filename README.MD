# Dataiku custom auth for OKTA integration

Note: This custom auth is not supported by dataiku and serves as an example.


## Build the plugin

- Setup the env variable `DKUINSTALLDIR` to the dataiku install dir
- Package the plugin `mvn package`


## Install the plugin into a DSS instance

- copy the jar `target/okta-1.0-SNAPSHOT-jar-with-dependencies.jar` into the dss instance, in `/data/dataiku/dss_data/lib/java/`
- Setup the env variables via the bin/env-site.sh script
    - `OKTA_API_KEY` : the Okta api key that you generated from the okta dev portal
    - `OKTA_ORG_URL`: the okta org url
- Restart DSS
- Setup the custom auth properties with the properties:
  - `Custom user supplier full class name`: `com.example.customauth.SampleCustomUserSupplier`