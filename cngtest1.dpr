program cngtest1;

{$APPTYPE CONSOLE}

uses
  SysUtils,
  WinApi_BCrypt in 'WinApi_BCrypt.pas';

var
  status: NTSTATUS;
  hAlg: BCRYPT_ALG_HANDLE;

  cbData: Cardinal;

  cbHashObject: Cardinal;
  pbHashObject: Pointer;

  cbHash: Cardinal;
  pbHash: Pointer;

  hHash: BCRYPT_HASH_HANDLE;

  rgbMsg: string;


begin
  try

    status := 0;
    hAlg := nil;

    cbData := 0;

    cbHashObject := 0;
    pbHashObject := nil;

    cbHash := 0;
    pbHash := nil;

    hHash := nil;

    rgbMsg := 'hello';

    //open an algorithm handle
    hAlg := nil;
    status := BCryptOpenAlgorithmProvider(hAlg,
                                          BCRYPT_SHA256_ALGORITHM,
                                          nil,
                                          0);

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

    //create a hash
    status := BCryptCreateHash(hAlg,
                               hHash,
                               pbHashObject,
                               cbHashObject,
                               nil,
                               0,
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

    BCryptCloseAlgorithmProvider(hAlg,0);
    BCryptDestroyHash(hHash);
    FreeMem(pbHashObject);
    FreeMem(pbHash);
  except
    on E:Exception do
      Writeln(E.Classname, ': ', E.Message);
  end;
end.
