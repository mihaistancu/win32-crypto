#include <windows.h>
#include <wincrypt.h>

PCCERT_CONTEXT GetCertificate(HCERTSTORE hCertStore)
{
	return CertFindCertificateInStore(
		hCertStore,
		PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
		0,
		CERT_FIND_SUBJECT_STR,
		L"leaf",
		NULL);
}

bool CheckOcsp(PCCERT_CONTEXT pCertContext)
{
	PVOID dwCertPtr[] = { (PVOID)pCertContext };

	CERT_REVOCATION_STATUS revocationStatus;
	revocationStatus.cbSize = sizeof(CERT_REVOCATION_STATUS);

	return CertVerifyRevocation(
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		CERT_CONTEXT_REVOCATION_TYPE,
		1,
		dwCertPtr,
		CERT_VERIFY_REV_SERVER_OCSP_FLAG,
		NULL,
		&revocationStatus);
}

bool CheckCrl(PCCERT_CONTEXT pCertContext)
{	
	DWORD size;

	CryptGetObjectUrl(
		URL_OID_CERTIFICATE_CRL_DIST_POINT,
		(LPVOID)pCertContext,
		0,
		NULL,
		&size,
		NULL,
		NULL,
		NULL);

	PCRYPT_URL_ARRAY pUrlArray = (PCRYPT_URL_ARRAY)HeapAlloc(GetProcessHeap(), 0, size);

	CryptGetObjectUrl(
		URL_OID_CERTIFICATE_CRL_DIST_POINT,
		(LPVOID)pCertContext,
		0,
		pUrlArray,
		&size,
		NULL,
		NULL,
		NULL);
	
	HeapFree(GetProcessHeap(), 0, pUrlArray);

	return false;
}

void main()
{
	HCERTSTORE hCertStore = CertOpenSystemStore(NULL, L"My");

	PCCERT_CONTEXT pCertContext = GetCertificate(hCertStore);

	BOOL isOcspValid = CheckOcsp(pCertContext);

	BOOL isCrlValid = CheckCrl(pCertContext);

	CertFreeCertificateContext(pCertContext);

	CertCloseStore(hCertStore, 0);
}