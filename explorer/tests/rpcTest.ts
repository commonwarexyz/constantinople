import { createConnectRouter, type ServiceImpl } from '@connectrpc/connect';
import { createFetchHandler } from '@connectrpc/connect/protocol';
import { ExplorerService } from '../src/gen/constantinople/explorer/v1/explorer_pb.ts';

/** Uses Connect's server implementation to exercise the browser transport and generated codecs. */
export function explorerFetch(implementation: Partial<ServiceImpl<typeof ExplorerService>>): typeof fetch {
    const router = createConnectRouter({ grpc: false, grpcWeb: false, connect: true });
    router.service(ExplorerService, implementation);
    return async (input, init) => {
        const request = new Request(input, init);
        const handler = router.handlers.find((candidate) => candidate.requestPath === new URL(request.url).pathname);
        if (!handler) return new Response(null, { status: 404 });
        return createFetchHandler(handler)(request);
    };
}
