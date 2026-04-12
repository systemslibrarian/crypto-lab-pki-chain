export interface Certificate {
  subject: string;
  issuer: string;
  publicKey: CryptoKey;
  signature: ArrayBuffer;
  validFrom: string;
  validTo: string;
  serialNumber: string;
}

export interface DemoChain {
  root: Certificate;
  intermediate: Certificate;
  leaf: Certificate;
}

export async function createDemoChain(): Promise<DemoChain> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    true,
    ['sign', 'verify'],
  );

  const now = new Date();
  const nextYear = new Date(now);
  nextYear.setFullYear(now.getFullYear() + 1);

  const cert: Certificate = {
    subject: 'CN=example.com',
    issuer: 'CN=Example Root',
    publicKey: keyPair.publicKey,
    signature: new ArrayBuffer(0),
    validFrom: now.toISOString(),
    validTo: nextYear.toISOString(),
    serialNumber: '0001',
  };

  return {
    root: cert,
    intermediate: cert,
    leaf: cert,
  };
}