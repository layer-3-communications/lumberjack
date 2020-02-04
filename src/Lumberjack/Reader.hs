{-# language BangPatterns #-}
{-# language BlockArguments #-}
{-# language DataKinds #-}
{-# language LambdaCase #-}
{-# language TypeApplications #-}

module Lumberjack.Reader
  ( Frame(..)
  , Uncompressed(..)
  , read
  ) where

import Prelude hiding (read)
import Data.Word (Word8,Word32)
import Data.Foldable (foldl')
import Data.Bytes.Types (MutableBytes(MutableBytes))
import Socket.Stream.IPv4 (Connection)
import Socket.Stream.IPv4 (Interruptibility(Uninterruptible))
import Socket.Stream.IPv4 (SendException(..),ReceiveException(..))
import Data.Chunks (Chunks)
import Data.Bytes (Bytes)
import Data.Primitive (ByteArray)
import Socket.Stream.Uninterruptible.MutableBytes (send)
import Socket.Stream.Uninterruptible.Bytes (receiveExactly)

import qualified Data.Builder.ST as Builder
import qualified Data.Bytes as Bytes
import qualified Data.Bytes.Chunks as Chunks
import qualified Data.Primitive as PM
import qualified Data.Primitive.ByteArray.BigEndian as BE
import qualified Data.Bytes.Parser.Latin as Latin
import qualified Data.Bytes.Parser.BigEndian as BE
import qualified Data.Bytes.Parser as Parser
import qualified Zlib

data Frame
  = Compressed
      !ByteArray -- ^ Compressed frames
      !(Chunks Uncompressed) -- ^ Decompressed frames
  | Uncompressed {-# UNPACK #-} !Uncompressed

data Uncompressed
  = Json
      !Word32 -- ^ Sequence number
      {-# UNPACK #-} !Bytes -- ^ Raw JSON bytes 

data Exception
  = ClosedConnection
    -- ^ This is normal and does not indicate a problem. The connection
    -- should be closed after this happens.
  | ClosedConnectionPoorly
    -- ^ The peer closed the connection when the were supposed to send
    -- more data.
  | ResetConnection
    -- ^ The peer ungracefully closed the connection. There may be a
    -- firewall, or the lumberjack protocol may be implemented incorrectly
    -- by either the reader or the writer.
  | Unreachable
    -- ^ There is a networking problem.
  | VersionOne
    -- ^ The writer is using version one of the lumberjack protocol.
  | InvalidVersion
    -- ^ The writer specified a lumberjack protocol version that
    -- does not exist.
  | InvalidFrameType
    -- ^ The writer specified a lumberjack protocol version that
    -- does not exist.
  | MalformedCompressedFrame
    -- ^ A compressed frame could not be parsed.
  | ReceivedData
    -- ^ The writer sent a data frame. This should not actually be
    -- an exception, but data frames are not yet supported by this
    -- library.

decompress :: Bytes -> Maybe (Chunks Uncompressed)
decompress !raw = do
  contents <- either (\_ -> Nothing) (Just . Chunks.concat) (Zlib.decompress raw)
  Parser.parseBytesMaybe
    ( let go !bldr = Latin.opt >>= \case
            Nothing -> Parser.effect (Builder.freeze bldr)
            Just c -> case c of
              '2' -> Parser.any () >>= \case
                -- We only support JSON.
                0x4A -> do
                  !seqNo <- BE.word32 ()
                  !szW <- BE.word32 ()
                  let sz = fromIntegral @Word32 @Int szW
                  !rawJson <- Parser.take () sz
                  let !v = Json seqNo rawJson
                  go =<< Parser.effect (Builder.push v bldr)
                _ -> Parser.fail ()
              _ -> Parser.fail ()
      in Parser.effect Builder.new >>= go
    ) contents

read :: Connection -> IO (Either Exception Frame)
read conn = receiveExactly conn (1 + 1 + 4) >>= \case
  Left err -> case err of
    ReceiveShutdown -> pure (Left ClosedConnection)
    ReceiveReset -> pure (Left ResetConnection)
    ReceiveHostUnreachable -> pure (Left Unreachable)
  Right barr -> do
    let version = PM.indexByteArray barr 0 :: Word8
        frameType = PM.indexByteArray barr 1 :: Word8
        u32 = BE.indexUnalignedByteArray barr 2 :: Word32
    case version of
      0x32 -> case frameType of
        -- Ignore the maximum unacknowledged frame count since we always
        -- send acks every time we receive anything.
        0x57 -> read conn  
        -- We do not support data frames yet.
        0x44 -> pure (Left ReceivedData)
        -- Compressed payloads are very similar to JSON payloads.
        -- The user is responsible for performing decompression.
        0x43 -> receiveExactly conn 4 >>= \case
          Left err -> case err of
            ReceiveShutdown -> pure (Left ClosedConnectionPoorly)
            ReceiveReset -> pure (Left ResetConnection)
            ReceiveHostUnreachable -> pure (Left Unreachable)
          Right barrSz -> do
            let szW = BE.indexByteArray barrSz 0 :: Word32
            let sz = fromIntegral @Word32 @Int szW
            receiveExactly conn sz >>= \case
              Left err -> case err of
                ReceiveShutdown -> pure (Left ClosedConnectionPoorly)
                ReceiveReset -> pure (Left ResetConnection)
                ReceiveHostUnreachable -> pure (Left Unreachable)
              Right payload -> case decompress (Bytes.fromByteArray payload) of
                Just chunks -> ack (lastSequenceNumber chunks) conn >>= \case
                  Left err -> case err of
                    SendShutdown -> pure (Left ClosedConnectionPoorly)
                    SendReset -> pure (Left ResetConnection)
                  Right _ -> pure (Right (Compressed payload chunks))
                Nothing -> pure (Left MalformedCompressedFrame)
        -- It is up to the user to decode the JSON payload.
        0x4A -> receiveExactly conn 4 >>= \case
          Left err -> case err of
            ReceiveShutdown -> pure (Left ClosedConnectionPoorly)
            ReceiveReset -> pure (Left ResetConnection)
            ReceiveHostUnreachable -> pure (Left Unreachable)
          Right barrSz -> do
            let szW = BE.indexByteArray barrSz 0 :: Word32
            let sz = fromIntegral @Word32 @Int szW
                seqNo = u32
            receiveExactly conn sz >>= \case
              Left err -> case err of
                ReceiveShutdown -> pure (Left ClosedConnectionPoorly)
                ReceiveReset -> pure (Left ResetConnection)
                ReceiveHostUnreachable -> pure (Left Unreachable)
              Right payload -> ack seqNo conn >>= \case
                Left err -> case err of
                  SendShutdown -> pure (Left ClosedConnectionPoorly)
                  SendReset -> pure (Left ResetConnection)
                Right _ -> do
                  let !payload' = Bytes.fromByteArray payload
                  pure (Right (Uncompressed (Json seqNo payload')))
        _ -> pure (Left InvalidFrameType)
      0x31 -> pure (Left VersionOne)
      _ -> pure (Left InvalidVersion)

ack :: Word32 -> Connection -> IO (Either (SendException 'Uninterruptible) ())
ack !seqNo !conn = do
  dst <- PM.newByteArray 8
  PM.writeByteArray dst 2 (0x32 :: Word8)
  PM.writeByteArray dst 3 (0x41 :: Word8)
  BE.writeByteArray dst 1 (seqNo :: Word32)
  send conn (MutableBytes dst 2 6)

lastSequenceNumber :: Chunks Uncompressed -> Word32
lastSequenceNumber = foldl' (\_ (Json seqNo _) -> seqNo) (0 :: Word32)
