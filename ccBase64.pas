unit ccBase64;

interface

function EncodeBase64(pData: Pointer; iData: Integer) : string;
function EncodeBase64Url(pData: Pointer; iData: Integer) : string;

implementation

uses
  SysUtils,
  Windows;
  
const
  CRYPT_STRING_BASE64 = $00000001;
  CRYPT_STRING_NOCRLF = $40000000;

function CryptBinaryToStringA(
  pbBinary: Pointer;
  cbBinary: Integer;
  dwFlags: Integer;
  pszString: PChar;
  var pcchString: Cardinal) : BOOL; winapi; external 'crypt32.dll';

function EncodeBase64(pData: Pointer; iData: Integer) : string;
var
  dwLen: Cardinal;
begin
  Result := '';
  dwLen := 0;
  CryptBinaryToStringA(pData, iData, CRYPT_STRING_BASE64 Or CRYPT_STRING_NOCRLF, nil, dwLen);
  SetLength(Result, dwLen);
  CryptBinaryToStringA(pData, iData, CRYPT_STRING_BASE64 Or CRYPT_STRING_NOCRLF, @Result[1], dwLen);
  Result := Trim(Result);
end;

function EncodeBase64Url(pData: Pointer; iData: Integer) : string;
begin
  Result := EncodeBase64(pData, iData);
  Result := StringReplace(Result, '+', '-', [rfReplaceAll]);
  Result := StringReplace(Result, '/', '_', [rfReplaceAll]);
  Result := StringReplace(Result, '=', '', [rfReplaceAll]);
end;

end.
