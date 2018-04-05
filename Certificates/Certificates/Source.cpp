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

	CertFreeCertificateContext(pCertContext);

	CertCloseStore(hCertStore, 0);
}