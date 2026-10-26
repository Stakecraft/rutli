# License texts for bundled JVM dependencies

`scripts/third-party-licenses.sh` builds `driver/THIRD-PARTY-LICENSES.txt` (shipped inside
`rutli-driver.jar` under `META-INF/rutli/`) from each dependency's POM and from the license and
notice files inside its jar. This directory holds the texts a jar does not carry itself:

| File | Source |
|---|---|
| `MPL-2.0.txt` | https://www.mozilla.org/media/MPL/2.0/index.txt (pureconfig) |
| `protobuf-java-LICENSE.txt` | https://github.com/protocolbuffers/protobuf/blob/v29.3/LICENSE |
| `animal-sniffer-annotations-LICENSE.txt` | https://github.com/mojohaus/animal-sniffer/blob/animal-sniffer-1.27/LICENSE |

Update the matching file when one of these dependencies changes version.
