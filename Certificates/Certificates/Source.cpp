#include <windows.h>

void main()
{
	HCERTSTORE hCertStore = CertOpenSystemStore(NULL, L"My");

	PCCERT_CONTEXT pCertContext = CertFindCertificateInStore(
		hCertStore,
		PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
		0,
		CERT_FIND_SUBJECT_STR,
		L"leaf",
		NULL);

	PVOID dwCertPtr[] = { (PVOID)pCertContext };

	CERT_REVOCATION_STATUS revocationStatus;
	revocationStatus.cbSize = sizeof(CERT_REVOCATION_STATUS);

	BOOL verificationResult = CertVerifyRevocation(
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		CERT_CONTEXT_REVOCATION_TYPE,
		1,
		dwCertPtr,
		CERT_VERIFY_REV_SERVER_OCSP_FLAG,
		NULL,
		&revocationStatus);

	CertFreeCertificateContext(pCertContext);

	CertCloseStore(hCertStore, 0);
}