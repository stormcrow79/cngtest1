program cngtest1;

{$APPTYPE CONSOLE}

uses
  SysUtils, Windows,
  WinApi_BCrypt in 'WinApi_BCrypt.pas';

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

var
  status: NTSTATUS;
  hAlg: BCRYPT_ALG_HANDLE;

  cbData: Cardinal;

  cbHashObject: Cardinal;
  pbHashObject: Pointer;

  cbHash: Cardinal;
  pbHash: Pointer;

  cbKey: Cardinal;
  pKey: Pointer;

  hHash: BCRYPT_HASH_HANDLE;

  rgbMsg: string;
  sExpectedHash: string;
  sHash: string;

begin
  try
    //rgbMsg := 'hello';
    //sExpectedHash := 'aGVsbG8=';

    rgbMsg := 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ';
    sExpectedHash := 'kXSdJhhUKTJemgs8O0rfIJmUaxoSIDdClL_OPmaC7Eo';

    //open an algorithm handle
    status := BCryptOpenAlgorithmProvider(hAlg,
                                          BCRYPT_SHA256_ALGORITHM,
                                          nil,
                                          BCRYPT_ALG_HANDLE_HMAC_FLAG);

    //calculate the size of the buffer to hold the hash object
    status := BCryptGetProperty(hAlg,
                                BCRYPT_OBJECT_LENGTH,
                                @cbHashObject,
                                sizeof(Integer),
                                cbData,
                                0);

    //allocate the hash object on the heap
    GetMem(pbHashObject, cbHashObject);

   //calculate the length of the hash
    status := BCryptGetProperty(hAlg,
                                BCRYPT_HASH_LENGTH,
                                @cbHash,
                                sizeof(Integer),
                                cbData,
                                0);

    //allocate the hash buffer on the heap
    GetMem(pbHash, cbHash);

    pKey := PChar('password');
    cbKey := Length('password');

    //create a hash
    status := BCryptCreateHash(hAlg,
                               hHash,
                               pbHashObject,
                               cbHashObject,
                               //nil, 0,
                               pKey, cbKey,
                               0);

    //hash some data
    status := BCryptHashData(hHash,
                             @rgbMsg[1],
                             length(rgbMsg),
                             0);

    //close the hash
    status := BCryptFinishHash(hHash,
                               pbHash,
                               cbHash,
                               0);

    sHash := EncodeBase64Url(pbHash, cbHash);

    BCryptCloseAlgorithmProvider(hAlg,0);
    BCryptDestroyHash(hHash);
    FreeMem(pbHashObject);
    FreeMem(pbHash);
  except
    on E:Exception do
      Writeln(E.Classname, ': ', E.Message);
  end;
end.
