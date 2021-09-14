Nebula Helper
-------------

Simple tool that works with [Nebula Mesh Admin](https://github.com/unreality/nebula-mesh-admin) to enroll or authorise mesh nodes.

### Usage

```commandline
Usage of nebula-helper:
  -action string
        action to run: enroll or oidc_login (default "oidc_login")
  -config_path string
        config path (default ".")
  -server string
        enrollment server
  -token string
        one time token for enrollment
```

### Examples
```commandline
nebula-helper -action=enroll -token=ABCD1234 -s
erver=http://localhost:8000/ -config_path=/etc/nebula
```

```commandline
nebula-helper -action=oidc_login -s
erver=http://localhost:8000/ -config_path=/etc/nebula
```

### Building

```commandline
git clone https://github.com/unreality/nebula-helper.git
cd nebula-helper
go build -o build/nebula-helper
```

### Todo

* Make `oidc_login` work on MacOS and Linux - at the moment it only works on windows.