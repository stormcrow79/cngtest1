program cngtest1;

{$APPTYPE CONSOLE}

uses
  SysUtils,
  Windows,
  WinApi_BCrypt in 'WinApi_BCrypt.pas',
  ccHash in 'ccHash.pas',
  ccBase64 in 'ccBase64.pas',
  ccJwt in 'ccJwt.pas';

var
  sMsg: string;
  sKey: string;
  sExpectedHash: string;

  pHash: Pointer;
  sHash: string;

begin
  try
    //rgbMsg := 'hello';
    //sExpectedHash := 'aGVsbG8';

    sMsg := 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ';
    sExpectedHash := 'kXSdJhhUKTJemgs8O0rfIJmUaxoSIDdClL_OPmaC7Eo';
    sKey := 'password';

    pHash := SHA256(@sMsg[1], Length(sMsg), @sKey[1], Length(sKey));
    sHash := EncodeBase64Url(pHash, SHA256_SIZE);
    FreeMem(pHash);

    Writeln(sExpectedHash = sHash);
    Readln;

  except
    on E:Exception do
      Writeln(E.Classname, ': ', E.Message);
  end;
end.
