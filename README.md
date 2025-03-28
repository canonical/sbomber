# Setup

Connect to the canonical VPN

    sudo snap install astral-uv
    cd src
    chmod +x sbomber
    alias sbomber=uv run ./src/sbomber


# Using SBOMber
## Prepare a manifest

Write to `./sbom_manifest.yaml` a specification of the packages you want to request SBOMs of.
```yaml
department: charming_engineering
email: luca.bello@canonical.com  # revenge is a dish best served cold
team: observability

artifacts:
  - name: parca-k8s
    revision: 299
    type: charm

  - name: jhack
    type: snap

  - name: /home/pietro/canonical/parca-k8s-operator/parca-k8s_ubuntu@24.04-amd64.charm
    type: local
```


## Fetch all packages and prepare the artifacts

> sbomber prepare

This will download the remote artifacts and copy the local ones to `./pkgs`, preparing them for upload.
The state will be saved in `./sbom_statefile.yaml`.


## Submit the artifacts

> sbomber submit


## Poll for status

This will update the statefile with the SBOM generation status for each artifact, as reported by the service. 
> sbomber poll

Alternatively, you can ask to block and wait for all artifacts to be ready:

> sbomber poll --wait --timeout 30  

NB: The timeout is in minutes, and applies to each artifact.


## Download all SBOMs

> sbomber download
 
This will download all ready SBOMs to `./sbombs`


## Additional configuration options

Check the CLI help for more parameters and options.

