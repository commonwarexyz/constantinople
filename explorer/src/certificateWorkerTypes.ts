export interface ConfigureCertificateVerifierRequest {
    readonly kind: 'configure';
    readonly storeUrl: string;
    readonly simplexVerificationMaterial: string;
}

export interface WatchBlockCertificatesRequest {
    readonly kind: 'watch';
    readonly blocks: readonly WatchedBlockCertificate[];
}

export type CertificateWorkerRequest =
    | ConfigureCertificateVerifierRequest
    | WatchBlockCertificatesRequest;

export interface WatchedBlockCertificate {
    readonly height: number;
    readonly digest: Uint8Array;
}

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
