export interface ConfigureCertificateVerifierRequest {
    readonly kind: 'configure';
    readonly storeUrl: string;
    readonly simplexVerificationMaterial: string;
}

export interface VerifyBlockCertificatesRequest {
    readonly kind: 'verify';
    readonly heights: readonly number[];
}

export type CertificateWorkerRequest =
    | ConfigureCertificateVerifierRequest
    | VerifyBlockCertificatesRequest;

export type CertificateWorkerResponse =
    | {
          readonly kind: 'verified';
          readonly height: number;
          readonly view: string;
      }
    | {
          readonly kind: 'error';
          readonly height: number;
          readonly detail: string;
      };
