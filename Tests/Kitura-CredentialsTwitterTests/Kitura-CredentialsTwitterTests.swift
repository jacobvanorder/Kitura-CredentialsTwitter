/**
 * Copyright Jacob Van Order 2017
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

import XCTest
@testable import Kitura_CredentialsTwitter

let consumerKey = "UdYo5tCHu8HdmY1uIoZxg1kNA"
let consumerSecret = "MacxkjCjsLgckelqTNQkQBB3WVLKYhb48VZOD7l51rmt1WcFtV"
let oAuthToken = "z1obMQAAAFAAynC1AAABWaLpD3U"
let oAuthTokenSecret = "g5qyyHw7txbYaLWZpFgl77wEtjHohgRf"
let oAuthTokenVerifier = "3lEFtnq9wzKavfSYSnPyntsLOk8FpOkE"

let parametersForRequest: [String : String] = ["oauth_consumer_key" : consumerKey,
                                               "oauth_nonce" : "HEYTHEREBL1MPYBOY",
                                               "oauth_signature_method" : "HMAC-SHA1",
                                               "oauth_timestamp" : "1484496492",
                                               "oauth_version" : "1.0"]

let parametersForAuth: [String : String] = ["oauth_consumer_key" : consumerKey,
                                            "oauth_nonce" : "FLY1NGTHROUGHTHESKYSOFANCYFREE",
                                            "oauth_signature_method" : "HMAC-SHA1",
                                            "oauth_timestamp" : "1484496900",
                                            "oauth_token":  oAuthToken,
                                            "oauth_version" : "1.0",
                                            "oauth_verifier" : oAuthTokenVerifier]

let twitterRequestResponse: Data = "1=2&3=4".data(using: String.Encoding.utf8)!
let twitterRequestResponseNotString: Data = Data()
let twitterRequestResponseNoQueries = "AmberDempsey".data(using: String.Encoding.utf8)!
let twitterRequestResponseNoKeyValues = "LittleMissSpringfield&WhichOneWillItBe&Me".data(using: String.Encoding.utf8)!

#if os(Linux)
    extension CredentialsTwitterTests {
        static var allTests : [(String, (CredentialsTwitterTests) -> () throws -> Void)] {
            return [
                ("testSecretStringForRequest", testSecretStringForRequest),
                ("testOAuthAuthorizationStringForRequest", testOAuthAuthorizationStringForRequest),
                ("testSecretStringForAuth", testSecretStringForAuth),
                ("testOAuthAuthorizationStringForAuth", testOAuthAuthorizationStringForAuth),
                ("testTwitterResponseDictionary", testTwitterResponseDictionary),
                ("testBadDataTwitterResponseDictionary", testBadDataTwitterResponseDictionary),
                ("testNoQueriesTwitterResponseDictionary", testNoQueriesTwitterResponseDictionary),
                ("testNoKeysValuesTwitterResponseDictionary", testNoKeysValuesTwitterResponseDictionary),
            ]
        }
    }
#endif

public class CredentialsTwitterTests: XCTestCase {
    public func testSecretStringForRequest() {
        let signature = String.oAuthSignature(fromMethod: "POST",
                                              urlString: "https://api.twitter.com/oauth/request_token",
                                              parameters: parametersForRequest,
                                              consumerSecret: consumerSecret)
        XCTAssertEqual(signature, "AtzhrRroa4Z41uZF8aIfMebd26g%3D")
    }
    
    public func testOAuthAuthorizationStringForRequest() {
        var parameters = parametersForRequest
        let signature = String.oAuthSignature(fromMethod: "POST",
                                              urlString: "https://api.twitter.com/oauth/request_token",
                                              parameters: parameters,
                                              consumerSecret: consumerSecret)
        parameters["oauth_signature"] = signature
        
        let oAuthAuthorizationHeaderString = String.oAuthAuthorizationString(fromParameters: parameters)
        XCTAssertEqual(oAuthAuthorizationHeaderString, "OAuth oauth_consumer_key=\"UdYo5tCHu8HdmY1uIoZxg1kNA\",oauth_nonce=\"HEYTHEREBL1MPYBOY\",oauth_signature=\"AtzhrRroa4Z41uZF8aIfMebd26g%3D\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\"1484496492\",oauth_version=\"1.0\"")
    }
    
    public func testSecretStringForAuth() {
        let url = "https://api.twitter.com/oauth/access_token?oauth_verifier=\(oAuthTokenVerifier)"
        let signature = String.oAuthSignature(fromMethod: "POST",
                                              urlString: url,
                                              parameters: parametersForAuth,
                                              consumerSecret: consumerSecret,
                                              oAuthToken: oAuthTokenSecret)
        XCTAssertEqual(signature, "OXH4boFCnH6sQXFCOTxC3SUCUVc%3D")
    }
    
    public func testOAuthAuthorizationStringForAuth() {
        var parameters = parametersForAuth
        let url = "https://api.twitter.com/oauth/access_token?oauth_verifier=\(oAuthTokenVerifier)"
        let signature = String.oAuthSignature(fromMethod: "POST",
                                              urlString: url,
                                              parameters: parameters,
                                              consumerSecret: consumerSecret,
                                              oAuthToken: oAuthTokenSecret)
        parameters["oauth_signature"] = signature
        
        let oAuthAuthorizationHeaderString = String.oAuthAuthorizationString(fromParameters: parameters)
        XCTAssertEqual(oAuthAuthorizationHeaderString, "OAuth oauth_consumer_key=\"UdYo5tCHu8HdmY1uIoZxg1kNA\",oauth_nonce=\"FLY1NGTHROUGHTHESKYSOFANCYFREE\",oauth_signature=\"OXH4boFCnH6sQXFCOTxC3SUCUVc%3D\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\"1484496900\",oauth_token=\"z1obMQAAAFAAynC1AAABWaLpD3U\",oauth_verifier=\"3lEFtnq9wzKavfSYSnPyntsLOk8FpOkE\",oauth_version=\"1.0\"")
    }
    
    public func testTwitterResponseDictionary() {
        do {
            let responseDictionary = try twitterRequestResponse.twitterResponseDictionary()
            XCTAssertEqual(responseDictionary["1"], "2")
            XCTAssertEqual(responseDictionary["3"], "4")
        }
        catch {
            XCTAssert(true, "twitter response dictionary not correct")
        }
    }
    
    public func testBadDataTwitterResponseDictionary() {
        do {
            _ = try twitterRequestResponseNotString.twitterResponseDictionary()
            XCTAssert(true, "Twitter response dictionary succeeded despite bad data.")
        }
        catch TwitterResponseError.dataNotString {
            
        }
        catch {
            XCTAssert(true, "Twitter response dictionary gave bad error.")
        }
    }
    
    public func testNoQueriesTwitterResponseDictionary() {
        do {
            _ = try twitterRequestResponseNoQueries.twitterResponseDictionary()
            XCTAssert(true, "Twitter response dictionary succeeded despite no queries.")
        }
        catch TwitterResponseError.noQueryComponents(let string) {
            XCTAssertEqual(string, "AmberDempsey")
        }
        catch {
            XCTAssert(true, "Twitter response dictionary gave bad error for no query string.")
        }
    }
    
    public func testNoKeysValuesTwitterResponseDictionary() {
        do {
            _ = try twitterRequestResponseNoQueries.twitterResponseDictionary()
            XCTAssert(true, "Twitter response dictionary succeeded despite no no key value pairs.")
        }
        catch TwitterResponseError.noQueryComponents(let string) {
            XCTAssertEqual(string, "LittleMissSpringfield&WhichOneWillItBe&Me")
        }
        catch {
            XCTAssert(true, "Twitter response dictionary gave bad error for no key values string.")
        }
    }
}
