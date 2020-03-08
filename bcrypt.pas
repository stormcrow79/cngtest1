unit bcrypt;

interface

Type
  NTSTATUS = Integer;

  BCRYPT_HANDLE = Integer;
  BCRYPT_ALG_HANDLE = BCRYPT_HANDLE;
  BCRYPT_HASH_HANDLE = BCRYPT_HANDLE;

Const

  BCRYPT_SHA256_ALGORITHM : PWideChar = 'SHA256';

// BCryptGetProperty strings
BCRYPT_OBJECT_LENGTH : PWideChar = 'ObjectLength';
{#define BCRYPT_ALGORITHM_NAME       L"AlgorithmName"
#define BCRYPT_PROVIDER_HANDLE      L"ProviderHandle"
#define BCRYPT_CHAINING_MODE        L"ChainingMode"
#define BCRYPT_BLOCK_LENGTH         L"BlockLength"
#define BCRYPT_KEY_LENGTH           L"KeyLength"
#define BCRYPT_KEY_OBJECT_LENGTH    L"KeyObjectLength"
#define BCRYPT_KEY_STRENGTH         L"KeyStrength"
#define BCRYPT_KEY_LENGTHS          L"KeyLengths"
#define BCRYPT_BLOCK_SIZE_LIST      L"BlockSizeList"
#define BCRYPT_EFFECTIVE_KEY_LENGTH L"EffectiveKeyLength"}
BCRYPT_HASH_LENGTH : PWideChar = 'HashDigestLength';
{#define BCRYPT_HASH_OID_LIST        L"HashOIDList"
#define BCRYPT_PADDING_SCHEMES      L"PaddingSchemes"
#define BCRYPT_SIGNATURE_LENGTH     L"SignatureLength"
#define BCRYPT_HASH_BLOCK_LENGTH    L"HashBlockLength"
#define BCRYPT_AUTH_TAG_LENGTH      L"AuthTagLength"}


Function BCryptOpenAlgorithmProvider(
  out phAlgorithm : BCRYPT_ALG_HANDLE;
  pszAlgId : PWideChar;
  pszImplementation : PWideChar;
  dwFlags : Integer) : NTSTATUS; external 'bcrypt.dll';

Function BCryptGetProperty(
  hObject : BCRYPT_HANDLE;
  pszProperty : PWideChar;
  pbOutput : Pointer;
  cbOutput : Integer;
  out pcbResult : Integer;
  dwFlags : Integer) : NTSTATUS; external 'bcrypt.dll';

Function BCryptCreateHash(
  hAlgorithm : BCRYPT_ALG_HANDLE;
  phHash : BCRYPT_HASH_HANDLE;
  pbHashObject : Pointer;
  cbHashObject : Integer;
  pbSecret : Pointer;
  cbSecret : Integer;
  dwFlags : Integer) : NTSTATUS; external 'bcrypt.dll';

Function BCryptHashData(
  hHash : BCRYPT_HASH_HANDLE;
  pbInput : Pointer;
  cbInput : Integer;
  dwFlags : Integer
) : NTSTATUS; external 'bcrypt.dll';

Function BCryptFinishHash(
  hHash : BCRYPT_HASH_HANDLE;
  pbOutput : Pointer;
  cbOutput : Integer;
  dwFlags : Integer
) : NTSTATUS; external 'bcrypt.dll';

Function BCryptDestroyHash(
  hHash : BCRYPT_HASH_HANDLE 
) : NTSTATUS; external 'bcrypt.dll';

Function BCryptCloseAlgorithmProvider(
  hAlgorithm : BCRYPT_ALG_HANDLE;
  dwFlags : Integer
) : NTSTATUS; external 'bcrypt.dll';

implementation

end.
