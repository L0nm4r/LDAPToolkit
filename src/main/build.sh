# build options for windows
# mac
SET CGO_ENABLED=0
SET GOOS=darwin
SET GOARCH=amd64
go build -ldflags "-s -w -extldflags \"-static\"" -o ldaptoolkit_mac_amd64 ./main/LDAPToolkit.go

SET CGO_ENABLED=0
SET GOOS=darwin
SET GOARCH=386
go build -ldflags "-s -w -extldflags \"-static\"" -o ldaptoolkit_mac_386 ./main/LDAPToolkit.go

# windows
SET CGO_ENABLED=0
SET GOOS=windows
SET GOARCH=amd64
go build -ldflags "-s -w -extldflags \"-static\"" -o ldaptoolkit_win_amd64.exe ./main/LDAPToolkit.go

SET CGO_ENABLED=0
SET GOOS=windows
SET GOARCH=386
go build -ldflags "-s -w -extldflags \"-static\"" -o ldaptoolkit_win_i386.exe ./main/LDAPToolkit.go
# linux
SET CGO_ENABLED=0
SET GOOS=linux
SET GOARCH=amd64
go build -ldflags "-s -w -extldflags \"-static\"" -o ldaptoolkit_linux_amd64.exe ./main/LDAPToolkit.go

SET CGO_ENABLED=0
SET GOOS=linux
SET GOARCH=386
go build -ldflags "-s -w -extldflags \"-static\"" -o ldaptoolkit_linux_i386.exe ./main/LDAPToolkit.go

