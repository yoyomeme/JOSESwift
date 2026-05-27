//
//  JWEECTests.swift
//  Tests
//
//  Created by Mikael Rucinsky on 07.12.20.
//
//  ---------------------------------------------------------------------------
//  Copyright 2024 Airside Mobile Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//  ---------------------------------------------------------------------------
//

import XCTest
import Security
@testable import JOSESwift

// swiftlint:disable force_unwrap

class JWEECTests: XCTestCase {

    let plaintext = "Lorem Ipsum"

    // MARK: - Key Generation Helpers

    private func generateECKeyPair(bits: Int) throws -> (privateKey: SecKey, publicKey: SecKey) {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
            kSecAttrKeySizeInBits as String: bits,
            kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: false]
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            if let err = error { throw err.takeRetainedValue() as Error }
            XCTFail("SecKeyCreateRandomKey returned nil without error")
            fatalError()
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            XCTFail("Failed to derive public key from private key")
            fatalError()
        }
        return (privateKey: privateKey, publicKey: publicKey)
    }

    // MARK: - All ECDH Algorithms × All Curves

    /// Test all four ECDH key management algorithms with P-256
    func testECDH_ES_A128KW_P256() throws {
        try roundtripTest(algorithm: .ECDH_ES_A128KW, encryption: .A256CBCHS512, bits: 256)
    }

    func testECDH_ES_A192KW_P256() throws {
        try roundtripTest(algorithm: .ECDH_ES_A192KW, encryption: .A256CBCHS512, bits: 256)
    }

    func testECDH_ES_A256KW_P256() throws {
        try roundtripTest(algorithm: .ECDH_ES_A256KW, encryption: .A256CBCHS512, bits: 256)
    }

    func testECDH_ES_P256() throws {
        try roundtripTest(algorithm: .ECDH_ES, encryption: .A256CBCHS512, bits: 256)
    }

    /// P-384 curve tests
    func testECDH_ES_A128KW_P384() throws {
        try roundtripTest(algorithm: .ECDH_ES_A128KW, encryption: .A256CBCHS512, bits: 384)
    }

    func testECDH_ES_P384() throws {
        try roundtripTest(algorithm: .ECDH_ES, encryption: .A256CBCHS512, bits: 384)
    }

    /// P-521 curve tests
    func testECDH_ES_A128KW_P521() throws {
        try roundtripTest(algorithm: .ECDH_ES_A128KW, encryption: .A256CBCHS512, bits: 521)
    }

    func testECDH_ES_P521() throws {
        try roundtripTest(algorithm: .ECDH_ES, encryption: .A256CBCHS512, bits: 521)
    }

    // MARK: - Content Encryption Algorithm Variants

    func testECDH_ES_A128KW_WithAESGCM() throws {
        try roundtripTest(algorithm: .ECDH_ES_A128KW, encryption: .A256GCM, bits: 256)
    }

    func testECDH_ES_WithA128CBC() throws {
        try roundtripTest(algorithm: .ECDH_ES, encryption: .A128CBCHS256, bits: 256)
    }

    // MARK: - Compact Serialization Roundtrip

    func testCompactSerializationRoundtrip() throws {
        let keyPair = try generateECKeyPair(bits: 256)
        let encrypter = try XCTUnwrap(Encrypter(keyManagementAlgorithm: .ECDH_ES_A128KW,
                                                contentEncryptionAlgorithm: .A256CBCHS512,
                                                encryptionKey: keyPair.publicKey))
        let decrypter = try XCTUnwrap(Decrypter(keyManagementAlgorithm: .ECDH_ES_A128KW,
                                                contentEncryptionAlgorithm: .A256CBCHS512,
                                                decryptionKey: keyPair.privateKey))

        let input = try XCTUnwrap(plaintext.data(using: .utf8))
        let header = JWEHeader(keyManagementAlgorithm: .ECDH_ES_A128KW, contentEncryptionAlgorithm: .A256CBCHS512)
        let jwe = try JWE(header: header, payload: Payload(input), encrypter: encrypter)

        // Test compact serialized string
        let serializedString = jwe.compactSerializedString
        let fromString = try JWE(compactSerialization: serializedString)
        XCTAssertEqual(try fromString.decrypt(using: decrypter).data(), input)

        // Test compact serialized data
        let serializedData = jwe.compactSerializedData
        let fromData = try JWE(compactSerialization: serializedData)
        XCTAssertEqual(try fromData.decrypt(using: decrypter).data(), input)
    }

    // MARK: - Small Payload

    func testSingleBytePayload() throws {
        let keyPair = try generateECKeyPair(bits: 256)
        let encrypter = try XCTUnwrap(Encrypter(keyManagementAlgorithm: .ECDH_ES_A128KW,
                                                contentEncryptionAlgorithm: .A256CBCHS512,
                                                encryptionKey: keyPair.publicKey))
        let decrypter = try XCTUnwrap(Decrypter(keyManagementAlgorithm: .ECDH_ES_A128KW,
                                                contentEncryptionAlgorithm: .A256CBCHS512,
                                                decryptionKey: keyPair.privateKey))

        let singleByte = Data([0x42])
        let header = JWEHeader(keyManagementAlgorithm: .ECDH_ES_A128KW, contentEncryptionAlgorithm: .A256CBCHS512)
        let jwe = try JWE(header: header, payload: Payload(singleByte), encrypter: encrypter)

        let serialized = jwe.compactSerializedString
        let decrypted = try JWE(compactSerialization: serialized).decrypt(using: decrypter)
        XCTAssertEqual(decrypted.data(), singleByte)
    }

    // MARK: - Large Payload

    func testLargePayload() throws {
        let keyPair = try generateECKeyPair(bits: 256)
        let encrypter = try XCTUnwrap(Encrypter(keyManagementAlgorithm: .ECDH_ES_A128KW,
                                                contentEncryptionAlgorithm: .A256CBCHS512,
                                                encryptionKey: keyPair.publicKey))
        let decrypter = try XCTUnwrap(Decrypter(keyManagementAlgorithm: .ECDH_ES_A128KW,
                                                contentEncryptionAlgorithm: .A256CBCHS512,
                                                decryptionKey: keyPair.privateKey))

        // 10KB payload
        let largeData = Data((0..<10240).map { _ in UInt8.random(in: 0...255) })
        let header = JWEHeader(keyManagementAlgorithm: .ECDH_ES_A128KW, contentEncryptionAlgorithm: .A256CBCHS512)
        let jwe = try JWE(header: header, payload: Payload(largeData), encrypter: encrypter)

        let serialized = jwe.compactSerializedString
        let decrypted = try JWE(compactSerialization: serialized).decrypt(using: decrypter)
        XCTAssertEqual(decrypted.data(), largeData)
    }

    // MARK: - Wrong Key Rejection

    func testDecryptionWithWrongKeyFails() throws {
        let keyPair1 = try generateECKeyPair(bits: 256)
        let keyPair2 = try generateECKeyPair(bits: 256)

        let encrypter = try XCTUnwrap(Encrypter(keyManagementAlgorithm: .ECDH_ES_A128KW,
                                                contentEncryptionAlgorithm: .A256CBCHS512,
                                                encryptionKey: keyPair1.publicKey))

        let input = try XCTUnwrap(plaintext.data(using: .utf8))
        let header = JWEHeader(keyManagementAlgorithm: .ECDH_ES_A128KW, contentEncryptionAlgorithm: .A256CBCHS512)
        let jwe = try JWE(header: header, payload: Payload(input), encrypter: encrypter)
        let serialized = jwe.compactSerializedString

        // Decrypting with wrong private key should throw (AES unwrap fails with wrong KEK)
        let wrongDecrypter = try XCTUnwrap(Decrypter(keyManagementAlgorithm: .ECDH_ES_A128KW,
                                                      contentEncryptionAlgorithm: .A256CBCHS512,
                                                      decryptionKey: keyPair2.privateKey))
        XCTAssertThrowsError(try JWE(compactSerialization: serialized).decrypt(using: wrongDecrypter))
    }

    // MARK: - Key Type Validation

    func testEncrypterRejectsPrivateKey() throws {
        let keyPair = try generateECKeyPair(bits: 256)
        // Passing a private key as encryption key should return nil
        let encrypter = Encrypter(keyManagementAlgorithm: .ECDH_ES_A128KW,
                                  contentEncryptionAlgorithm: .A256CBCHS512,
                                  encryptionKey: keyPair.privateKey)
        XCTAssertNil(encrypter, "Encrypter should reject a private SecKey for ECDH encryption")
    }

    func testDecrypterRejectsPublicKey() throws {
        let keyPair = try generateECKeyPair(bits: 256)
        // Passing a public key as decryption key should return nil
        let decrypter = Decrypter(keyManagementAlgorithm: .ECDH_ES_A128KW,
                                  contentEncryptionAlgorithm: .A256CBCHS512,
                                  decryptionKey: keyPair.publicKey)
        XCTAssertNil(decrypter, "Decrypter should reject a public SecKey for ECDH decryption")
    }

    func testEncrypterRejectsNonSecKey() {
        let encrypter = Encrypter(keyManagementAlgorithm: .ECDH_ES_A128KW,
                                  contentEncryptionAlgorithm: .A256CBCHS512,
                                  encryptionKey: Data())
        XCTAssertNil(encrypter, "Encrypter should reject Data for ECDH encryption")
    }

    func testDecrypterRejectsNonSecKey() {
        let decrypter = Decrypter(keyManagementAlgorithm: .ECDH_ES_A128KW,
                                  contentEncryptionAlgorithm: .A256CBCHS512,
                                  decryptionKey: "wrong")
        XCTAssertNil(decrypter, "Decrypter should reject String for ECDH decryption")
    }

    // MARK: - Algorithm Mismatch

    func testEncrypterAlgorithmMismatch() throws {
        let keyPair = try generateECKeyPair(bits: 256)
        let encrypter = try XCTUnwrap(Encrypter(keyManagementAlgorithm: .ECDH_ES_A128KW,
                                                contentEncryptionAlgorithm: .A256CBCHS512,
                                                encryptionKey: keyPair.publicKey))
        // Use a different algorithm in the header than what the encrypter was initialized with
        let mismatchedHeader = JWEHeader(keyManagementAlgorithm: .ECDH_ES_A256KW, contentEncryptionAlgorithm: .A256CBCHS512)
        XCTAssertThrowsError(try JWE(header: mismatchedHeader, payload: Payload(Data()), encrypter: encrypter))
    }

    // MARK: - Multiple Encryptions with Same Key Pair

    func testMultipleEncryptionsWithSameKeyPair() throws {
        let keyPair = try generateECKeyPair(bits: 256)
        let encrypter = try XCTUnwrap(Encrypter(keyManagementAlgorithm: .ECDH_ES_A128KW,
                                                contentEncryptionAlgorithm: .A256CBCHS512,
                                                encryptionKey: keyPair.publicKey))
        let decrypter = try XCTUnwrap(Decrypter(keyManagementAlgorithm: .ECDH_ES_A128KW,
                                                contentEncryptionAlgorithm: .A256CBCHS512,
                                                decryptionKey: keyPair.privateKey))

        for i in 0..<5 {
            let message = "Message \(i): \(String(repeating: "x", count: i * 100))"
            let input = try XCTUnwrap(message.data(using: .utf8))
            let header = JWEHeader(keyManagementAlgorithm: .ECDH_ES_A128KW, contentEncryptionAlgorithm: .A256CBCHS512)
            let jwe = try JWE(header: header, payload: Payload(input), encrypter: encrypter)

            let decrypted = try JWE(compactSerialization: jwe.compactSerializedString).decrypt(using: decrypter)
            XCTAssertEqual(decrypted.data(), input, "Round-trip failed for message \(i)")

            // Each encryption should produce a different ciphertext (different ephemeral key)
            if i > 0 {
                let prevHeader = JWEHeader(keyManagementAlgorithm: .ECDH_ES_A128KW, contentEncryptionAlgorithm: .A256CBCHS512)
                let prevJwe = try JWE(header: prevHeader, payload: Payload(input), encrypter: encrypter)
                XCTAssertNotEqual(jwe.compactSerializedString, prevJwe.compactSerializedString,
                                  "Different encryptions should produce different ciphertexts")
            }
        }
    }

    // MARK: - JWE Structure Validation

    func testJWEStructureContainsEPK() throws {
        let keyPair = try generateECKeyPair(bits: 256)
        let encrypter = try XCTUnwrap(Encrypter(keyManagementAlgorithm: .ECDH_ES_A128KW,
                                                contentEncryptionAlgorithm: .A256CBCHS512,
                                                encryptionKey: keyPair.publicKey))

        let input = try XCTUnwrap(plaintext.data(using: .utf8))
        let header = JWEHeader(keyManagementAlgorithm: .ECDH_ES_A128KW, contentEncryptionAlgorithm: .A256CBCHS512)
        let jwe = try JWE(header: header, payload: Payload(input), encrypter: encrypter)

        // The JWE header should contain an epk (ephemeral public key)
        XCTAssertNotNil(jwe.header.epk, "JWE header should contain ephemeral public key")
        XCTAssertEqual(jwe.header.epk?.crv, .P256, "EPK should be P-256 curve")
    }

    // MARK: - Helper

    private func roundtripTest(algorithm: KeyManagementAlgorithm, encryption: ContentEncryptionAlgorithm, bits: Int) throws {
        let keyPair = try generateECKeyPair(bits: bits)

        guard let encrypter = Encrypter(keyManagementAlgorithm: algorithm,
                                        contentEncryptionAlgorithm: encryption,
                                        encryptionKey: keyPair.publicKey) else {
            XCTFail("Failed to create encrypter for \(algorithm) with \(bits)-bit key")
            return
        }
        guard let decrypter = Decrypter(keyManagementAlgorithm: algorithm,
                                        contentEncryptionAlgorithm: encryption,
                                        decryptionKey: keyPair.privateKey) else {
            XCTFail("Failed to create decrypter for \(algorithm) with \(bits)-bit key")
            return
        }

        let input = try XCTUnwrap(plaintext.data(using: .utf8))
        let header = JWEHeader(keyManagementAlgorithm: algorithm, contentEncryptionAlgorithm: encryption)
        let jwe = try JWE(header: header, payload: Payload(input), encrypter: encrypter)
        let serialization = jwe.compactSerializedString

        let deserialization = try JWE(compactSerialization: serialization)
        let decrypted = try deserialization.decrypt(using: decrypter)
        XCTAssertEqual(input, decrypted.data(), "Round-trip failed for \(algorithm) with \(bits)-bit key")
    }
}
// swiftlint:enable force_unwrapping
