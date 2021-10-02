# opa-example
Open Policy Agent example

## Download opa

Following [Download Opa](https://www.openpolicyagent.org/docs/latest/#1-download-opa)

```
$ curl -L -o opa https://openpolicyagent.org/downloads/v0.33.0/opa_darwin_amd64
$ chmod 755 ./opa
```

## Test RBAC configuration (roles & permission)

```
$ opa test -v *.rego
```

## Embed rego files into go binary

In go 1.16 we can leverage [embed](https://pkg.go.dev/embed) component to embed rego file into go binary, save the I/O read time.
