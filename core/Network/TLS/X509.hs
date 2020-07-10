-- |
-- Module      : Network.TLS.X509
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- X509 helpers
--
module Network.TLS.X509
    ( CertificateChain(..)
    , Certificate(..)
    , SignedCertificate
    , getCertificate
    , isNullCertificateChain
    , getCertificateChainLeaf
    , CertificateRejectReason(..)
    , CertificateUsage(..)
    , CertificateStore
    , ValidationCache
    , exceptionValidationCache
    , validateDefault
    , FailedReason
    , ServiceID
    , wrapCertificateChecks
    , pubkeyType
    ) where

import Control.Exception (SomeException)
import Data.X509
import Data.X509.Validation
import Data.X509.CertificateStore

isNullCertificateChain :: CertificateChain -> Bool
isNullCertificateChain (CertificateChain l) = null l

getCertificateChainLeaf :: CertificateChain -> SignedExact Certificate
getCertificateChainLeaf (CertificateChain [])    = error "empty certificate chain"
getCertificateChainLeaf (CertificateChain (x:_)) = x

-- | Certificate and Chain rejection reason
data CertificateRejectReason =
          CertificateRejectExpired
        | CertificateRejectRevoked
        | CertificateRejectUnknownCA
        | CertificateRejectAbsent
        | CertificateRejectOther String (Maybe SomeException)
        deriving (Show)

-- | Certificate Usage callback possible returns values.
data CertificateUsage =
          CertificateUsageAccept                         -- ^ usage of certificate accepted
        | CertificateUsageReject CertificateRejectReason -- ^ usage of certificate rejected
        deriving (Show)

wrapCertificateChecks :: [FailedReason] -> CertificateUsage
wrapCertificateChecks [] = CertificateUsageAccept
wrapCertificateChecks l
    | Expired `elem` l   = CertificateUsageReject   CertificateRejectExpired
    | InFuture `elem` l  = CertificateUsageReject   CertificateRejectExpired
    | UnknownCA `elem` l = CertificateUsageReject   CertificateRejectUnknownCA
    | SelfSigned `elem` l = CertificateUsageReject  CertificateRejectUnknownCA
    | EmptyChain `elem` l = CertificateUsageReject  CertificateRejectAbsent
    | otherwise          = CertificateUsageReject $ CertificateRejectOther (show l) Nothing

pubkeyType :: PubKey -> String
pubkeyType = show . pubkeyToAlg
