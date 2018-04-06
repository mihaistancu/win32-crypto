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

PCRYPT_URL_ARRAY GetCrlUrls(PCCERT_CONTEXT pCertContext)
{
	LPCSTR pszUrlOid = URL_OID_CERTIFICATE_CRL_DIST_POINT;
	LPVOID pvPara = (LPVOID)pCertContext;
	DWORD dwFlags = 0;
	PCRYPT_URL_ARRAY pUrlArray = NULL;
	DWORD size;
	PCRYPT_URL_INFO pUrlInfo = NULL;
	DWORD* pcbUrlInfo = NULL;
	LPVOID pvReserved = NULL;

	CryptGetObjectUrl(pszUrlOid, pvPara, dwFlags, pUrlArray, &size, pUrlInfo, pcbUrlInfo, pvReserved);
	pUrlArray = (PCRYPT_URL_ARRAY)HeapAlloc(GetProcessHeap(), 0, size);
	CryptGetObjectUrl(pszUrlOid, pvPara, dwFlags, pUrlArray, &size, pUrlInfo, pcbUrlInfo, pvReserved);

	return pUrlArray;
}

PCCRL_CONTEXT DownloadCrl(LPWSTR pszUrl)
{
	PCCRL_CONTEXT pCrlContext;
	LPCSTR pszObjectOid = CONTEXT_OID_CRL;
	DWORD dwRetrievalFlags = 0;
	DWORD dwTimeout = 15000;
	LPVOID* ppvObject = (LPVOID*)&pCrlContext;
	HCRYPTASYNC hAsyncRetrieve = NULL;
	PCRYPT_CREDENTIALS pCredentials = NULL;
	LPVOID pvVerify = NULL;
	PCRYPT_RETRIEVE_AUX_INFO pAuxInfo = NULL;

	CryptRetrieveObjectByUrl(pszUrl, pszObjectOid, dwRetrievalFlags, dwTimeout, ppvObject, hAsyncRetrieve, pCredentials, pvVerify, pAuxInfo);

	return pCrlContext;
}

BOOL Verify(PCCERT_CONTEXT pCertContext, PCCRL_CONTEXT pCrlContext)
{
	DWORD dwFlags = 0;
	void* pvReserved = NULL;
	CRL_ENTRY crlEntry;
	PCRL_ENTRY pCrlEntry = &crlEntry;

	CertFindCertificateInCRL(pCertContext, pCrlContext, dwFlags, pvReserved, &pCrlEntry);

	return pCrlEntry == NULL;
}

bool CheckCrl(PCCERT_CONTEXT pCertContext)
{	
	BOOL result;
	
	PCRYPT_URL_ARRAY pUrlArray = GetCrlUrls(pCertContext);

	for (int i = 0; i < pUrlArray->cUrl; i++)
	{
		PCCRL_CONTEXT pCrlContext = DownloadCrl(pUrlArray->rgwszUrl[i]);

		if (pCrlContext == NULL) continue;

		result = Verify(pCertContext, pCrlContext);

		CertFreeCRLContext(pCrlContext);

		break;
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