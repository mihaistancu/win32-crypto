#include <windows.h>
#include <wincrypt.h>

PCCERT_CONTEXT GetCertificate(HCERTSTORE hCertStore)
{	
	DWORD dwEncoding = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;
	DWORD dwFindFlags = 0;
	DWORD dwFindType = CERT_FIND_SUBJECT_STR;
	const void* pvFindParam = L"leaf";
	PCCERT_CONTEXT pPrevCertContext = NULL;

	return CertFindCertificateInStore(hCertStore, dwEncoding, dwFindFlags, dwFindType, pvFindParam, pPrevCertContext);
}

bool CheckOcsp(PCCERT_CONTEXT pCertContext)
{
	DWORD dwEncoding = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;
	DWORD dwRevType = CERT_CONTEXT_REVOCATION_TYPE;
	DWORD cContext = 1;
	PVOID rgpvContext[] = { (PVOID)pCertContext };
	DWORD dwFlags = CERT_VERIFY_REV_SERVER_OCSP_FLAG;
	PCERT_REVOCATION_PARA pRevPara = NULL;
	CERT_REVOCATION_STATUS revocationStatus;
	revocationStatus.cbSize = sizeof(CERT_REVOCATION_STATUS);

	return CertVerifyRevocation(dwEncoding, dwRevType, cContext, rgpvContext, dwFlags, pRevPara, &revocationStatus);
}

bool CheckCrl(PCCERT_CONTEXT pCertContext)
{	
	BOOL result;
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

	for (int i = 0; i < pUrlArray->cUrl; i++)
	{
		PCCRL_CONTEXT pCrlContext;

		result = CryptRetrieveObjectByUrl(
			pUrlArray->rgwszUrl[i],
			CONTEXT_OID_CRL,
			0,
			15000,
			(LPVOID*)&pCrlContext,
			NULL,
			NULL,
			NULL,
			NULL
		);

		PCRL_INFO pCrlInfos[] = { pCrlContext->pCrlInfo };

		result = CertVerifyCRLRevocation(
			X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			pCertContext->pCertInfo,
			1,
			pCrlInfos);

		CertFreeCRLContext(pCrlContext);
	}
	
	HeapFree(GetProcessHeap(), 0, pUrlArray);

	return result;
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