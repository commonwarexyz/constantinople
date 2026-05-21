export interface EnqueueCertificateRequest {
    readonly kind: 'enqueue';
    readonly storeUrl: string;
    readonly simplexVerificationMaterial: string;
    readonly heights: number[];
}

export type CertificateWorkerRequest = EnqueueCertificateRequest;

export type CertificateWorkerResponse =
    | {
          readonly kind: 'fetching';
          readonly height: number;
      }
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
