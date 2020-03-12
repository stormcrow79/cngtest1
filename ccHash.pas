unit ccHash;

interface

const
  SHA256_SIZE = 32;

function SHA256(pData: Pointer; iData: Integer; pKey: Pointer; iKey: Integer): Pointer;

implementation

uses
  Windows,
  WinApi_BCrypt;

function SHA256(pData: Pointer; iData: Integer; pKey: Pointer; iKey: Integer): Pointer;
var
  status: NTSTATUS;
  hAlg: BCRYPT_ALG_HANDLE;
  hHash: BCRYPT_HASH_HANDLE;
  dwFlags: Cardinal;

  cbData: Cardinal;

  cbHashObject: Cardinal;
  pbHashObject: Pointer;

  cbHash: Cardinal;
  pbHash: Pointer;

begin
  Result := nil;

  hAlg := nil;
  hHash := nil;
  pbHashObject := nil;

  try
    // use HMAC if we got a key
    dwFlags := 0;
    if Assigned(pKey) then
      dwFlags := BCRYPT_ALG_HANDLE_HMAC_FLAG;

    //open an algorithm handle
    status := BCryptOpenAlgorithmProvider(hAlg,
                                          BCRYPT_SHA256_ALGORITHM,
                                          nil,
                                          dwFlags);
    if status <> 0 then
      exit;

    //calculate the size of the buffer to hold the hash object
    status := BCryptGetProperty(hAlg,
                                BCRYPT_OBJECT_LENGTH,
                                @cbHashObject,
                                sizeof(Integer),
                                cbData,
                                0);
    if status <> 0 then
      exit;

    //allocate the hash object on the heap
    GetMem(pbHashObject, cbHashObject);

    //calculate the length of the hash
    status := BCryptGetProperty(hAlg,
                                BCRYPT_HASH_LENGTH,
                                @cbHash,
                                sizeof(Integer),
                                cbData,
                                0);
    if status <> 0 then
      exit;

    //allocate the hash buffer on the heap
    GetMem(pbHash, cbHash);

    //create a hash
    status := BCryptCreateHash(hAlg,
                               hHash,
                               pbHashObject,
                               cbHashObject,
                               pKey, iKey,
                               0);
    if status <> 0 then
      exit;

    //hash some data
    status := BCryptHashData(hHash,
                             pData,
                             iData,
                             0);
    if status <> 0 then
      exit;

    //close the hash
    status := BCryptFinishHash(hHash,
                               pbHash,
                               cbHash,
                               0);
    if status <> 0 then
      exit;

    Result := pbHash;
  finally
    BCryptCloseAlgorithmProvider(hAlg, 0);
    BCryptDestroyHash(hHash);
    FreeMem(pbHashObject);
    //FreeMem(pbHash); // caller frees
  end;
end;

end.
