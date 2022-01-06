{-# language BangPatterns #-}
{-# language BlockArguments #-}
{-# language DataKinds #-}
{-# language LambdaCase #-}
{-# language ScopedTypeVariables #-}
{-# language TypeApplications #-}

module Lumberjack.Reader
  ( Frame(..)
  , Uncompressed(..)
  , Exception(..)
  , read
  ) where

import Prelude hiding (read)
import Data.Bifunctor (bimap)
import Data.Word (Word8,Word32)
import Data.Foldable (foldl')
import Data.Bytes.Types (MutableBytes(MutableBytes))
import Socket.Stream.IPv4 (Connection)
import Socket.Stream.IPv4 (Interruptibility(Uninterruptible))
import Socket.Stream.IPv4 (SendException(..),ReceiveException(..))
import Data.Chunks (Chunks)
import Data.Bytes.Types (Bytes(Bytes))
import Data.Primitive (ByteArray)
import Socket.Stream.Uninterruptible.MutableBytes (send,receiveExactly)

import qualified Data.Builder.ST as Builder
import qualified Data.Bytes as Bytes
import qualified Data.Bytes.Chunks as Chunks
import qualified Data.Primitive as PM
import qualified Data.Primitive.ByteArray.BigEndian as BE
import qualified Data.Bytes.Parser.Latin as Latin
import qualified Data.Bytes.Parser.BigEndian as BE
import qualified Data.Bytes.Parser as Parser
import qualified Socket.Stream.Uninterruptible.Bytes as StreamBytes
import qualified Zlib

-- | A lumberjack frame, either many compressed messages or a single
-- uncompressed message. In the case of compressed messages, the original
-- concatenated sequence (compressed with @DEFLATE@) is provided in case
-- the user wants to do something with it.
data Frame
  = Compressed
      !ByteArray -- ^ Compressed frames
      !(Chunks Uncompressed) -- ^ Decompressed frames
  | Uncompressed {-# UNPACK #-} !Uncompressed

-- | A single message. Only JSON messages are supported since all Elastic
-- beats have moved to this format. Note that this data type does not
-- validate or parse the JSON. It merely communicates that the frame
-- claims that the payload is JSON. Use the @json-syntax@ library to
-- decode this.
data Uncompressed
  = Json
      !Word32 -- ^ Sequence number
      {-# UNPACK #-} !Bytes -- ^ Raw JSON bytes 

-- | Anything that can go wrong. This includes socket-related issues and
-- parsing issues. It is not possible to recover from any of these, and
-- the best course of action is to log the exception and close the connection.
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
  | VersionThree
    -- ^ The writer is using version three of the lumberjack protocol.
  | VersionFour
    -- ^ The writer is using version three of the lumberjack protocol.
  | InvalidPreface
    -- ^ The preface claims that the version is greater than 4. This
    -- is probably not actually Lumberjack traffic.
  | InvalidFrameType
    -- ^ The writer specified a lumberjack protocol version that
    -- does not exist.
  | Decompression
    -- ^ A compressed frame could not be decompressed.
  | MalformedCompressedFrame
    -- ^ A compressed frame was decompressed successfully, but its
    -- payload was invalid.
  | ReceivedData
    -- ^ The writer sent a data frame. This should not actually be
    -- an exception, but data frames are not yet supported by this
    -- library.
  | LargeFrame
    -- ^ The writer sent a data frame larger than 16MB. To prevent
    -- both accidental and intentional DoS, we reject such frames.

decompress :: Bytes -> Either Exception (Chunks Uncompressed)
decompress !raw = do
  contents <- bimap (\_ -> Decompression) Chunks.concat (Zlib.decompress raw)
  Parser.parseBytesEither
    ( let go !bldr = Latin.opt >>= \case
            Nothing -> Parser.effect (Builder.freeze bldr)
            Just c -> case c of
              '2' -> Parser.any MalformedCompressedFrame >>= \case
                -- We only support JSON.
                0x4A -> do
                  !seqNo <- BE.word32 MalformedCompressedFrame
                  !szW <- BE.word32 MalformedCompressedFrame
                  let sz = fromIntegral @Word32 @Int szW
                  !rawJson <- Parser.take MalformedCompressedFrame sz
                  let !v = Json seqNo rawJson
                  go =<< Parser.effect (Builder.push v bldr)
                _ -> Parser.fail MalformedCompressedFrame
              _ -> Parser.fail MalformedCompressedFrame
      in Parser.effect Builder.new >>= go
    ) contents

-- | Receive and frame and decode its messages. This acknowledges every
-- frame after receiving it. 
read :: Connection -> IO (Either Exception Frame)
read conn = do
  recvBuf <- PM.newByteArray 8
  receiveExactly conn (MutableBytes recvBuf 2 6) >>= \case
    Left err -> case err of
      ReceiveShutdown -> pure (Left ClosedConnection)
      ReceiveReset -> pure (Left ResetConnection)
      ReceiveHostUnreachable -> pure (Left Unreachable)
    Right (_ :: ()) -> do
      version :: Word8 <- PM.readByteArray recvBuf 2
      frameType :: Word8 <- PM.readByteArray recvBuf 3
      u32 :: Word32 <- BE.readByteArray recvBuf 1
      case version of
        0x32 -> case frameType of
          -- Ignore the maximum unacknowledged frame count since we always
          -- send acks every time we receive anything.
          0x57 -> read conn  
          -- We do not support data frames yet.
          0x44 -> pure (Left ReceivedData)
          -- Compressed payloads are very similar to JSON payloads.
          -- The user is responsible for performing decompression.
          0x43 -> do
            let szW = u32
            if szW > 16777216
              then pure (Left LargeFrame)
              else do
                let sz = fromIntegral @Word32 @Int szW
                StreamBytes.receiveExactly conn sz >>= \case
                  Left err -> case err of
                    ReceiveShutdown -> pure (Left ClosedConnectionPoorly)
                    ReceiveReset -> pure (Left ResetConnection)
                    ReceiveHostUnreachable -> pure (Left Unreachable)
                  Right payload -> case decompress (Bytes payload 0 sz) of
                    Right chunks -> ack (lastSequenceNumber chunks) conn >>= \case
                      Left err -> case err of
                        SendShutdown -> pure (Left ClosedConnectionPoorly)
                        SendReset -> pure (Left ResetConnection)
                      Right _ -> pure (Right (Compressed payload chunks))
                    Left err -> pure (Left err)
          -- It is up to the user to decode the JSON payload.
          0x4A -> do
            let szW = u32
            if szW > 16777216
              then pure (Left LargeFrame)
              else do
                let sz = fromIntegral @Word32 @Int szW
                    seqNo = u32
                StreamBytes.receiveExactly conn sz >>= \case
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
        0x33 -> pure (Left VersionThree)
        0x34 -> pure (Left VersionFour)
        _ -> pure (Left InvalidPreface)

ack :: Word32 -> Connection -> IO (Either (SendException 'Uninterruptible) ())
ack !seqNo !conn = do
  dst <- PM.newByteArray 8
  PM.writeByteArray dst 2 (0x32 :: Word8)
  PM.writeByteArray dst 3 (0x41 :: Word8)
  BE.writeByteArray dst 1 (seqNo :: Word32)
  send conn (MutableBytes dst 2 6)

lastSequenceNumber :: Chunks Uncompressed -> Word32
lastSequenceNumber = foldl' (\_ (Json seqNo _) -> seqNo) (0 :: Word32)
