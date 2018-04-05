#include <windows.h>

void main()
{
	HCERTSTORE hCertStore = CertOpenSystemStore(NULL, L"My");

	CertCloseStore(hCertStore, 0);
}