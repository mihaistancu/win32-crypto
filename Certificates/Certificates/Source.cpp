#include <windows.h>

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

void main()
{
	HCERTSTORE hCertStore = CertOpenSystemStore(NULL, L"My");

	PCCERT_CONTEXT pCertContext = GetCertificate(hCertStore);

	BOOL isOcspValid = CheckOcsp(pCertContext);

	CertFreeCertificateContext(pCertContext);

	CertCloseStore(hCertStore, 0);
}