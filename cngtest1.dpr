program cngtest1;

{$APPTYPE CONSOLE}

uses
  SysUtils,
  bcrypt in 'bcrypt.pas';

var
  status: NTSTATUS;
  hAlg: BCRYPT_ALG_HANDLE;

  cbData: Integer;

  cbHashObject: Integer;
  pbHashObject: Pointer;

  cbHash: Integer;
  pbHash: Pointer;

  hHash: BCRYPT_HASH_HANDLE;

  rgbMsg: string;


begin
  try

    rgbMsg := 'hello';

    //open an algorithm handle
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
