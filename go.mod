module obrien

go 1.26.0

require (
	github.com/corazawaf/coraza-coreruleset/crs/v4 v4.30.0
	github.com/mailpile/kettlingar-go v0.0.0
)

require (
	github.com/corazawaf/libinjection-go v0.3.4 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/goccy/go-yaml v1.19.2 // indirect
	github.com/gotnospirit/makeplural v0.0.0-20180622080156-a5f48d94d976 // indirect
	github.com/gotnospirit/messageformat v0.0.0-20221001023931-dfe49f1eb092 // indirect
	github.com/kaptinlin/go-i18n v0.1.4 // indirect
	github.com/kaptinlin/jsonschema v0.4.6 // indirect
	github.com/magefile/mage v1.17.0 // indirect
	github.com/petar-dambovaliev/aho-corasick v0.0.0-20250424160509-463d218d4745 // indirect
	github.com/tidwall/gjson v1.18.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/valllabh/ocsf-schema-golang v1.0.3 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	rsc.io/binaryregexp v0.2.0 // indirect
)

require (
	github.com/corazawaf/coraza/v3 v3.0.0
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.4.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/sagikazarmark/locafero v0.11.0 // indirect
	github.com/sourcegraph/conc v0.3.1-0.20240121214520-5f936abd7ae8 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/spf13/cobra v1.10.2 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/spf13/viper v1.21.0 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/vmihailenco/msgpack/v5 v5.4.1 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)

// Always build against the local submodule, so changes made there are
// picked up without publishing a new kettlingar-go version.
replace github.com/mailpile/kettlingar-go => ./submodules/kettlingar-go

// Always build against the local submodule, so changes made there are
// picked up without publishing a new coraza version.
replace github.com/corazawaf/coraza/v3 => ./submodules/coraza
