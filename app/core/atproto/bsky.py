import atproto_identity.resolver
resolver = atproto_identity.resolver.IdResolver()
did = resolver.handle.resolve("lordlumineer.com")
did_doc = resolver.did.resolve(did)

import atproto_identity.did.atproto_data
atproto_data = atproto_identity.did.atproto_data.AtprotoData(did)

