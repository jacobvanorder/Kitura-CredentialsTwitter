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

var consumerKey = "UdYo5tCHu8HdmY1uIoZxg1kNA"
var consumerSecret = "MacxkjCjsLgckelqTNQkQBB3WVLKYhb48VZOD7l51rmt1WcFtV"
var oAuthToken = "z1obMQAAAFAAynC1AAABWaLpD3U"
var oAuthTokenSecret = "g5qyyHw7txbYaLWZpFgl77wEtjHohgRf"
var oAuthTokenVerifier = "3lEFtnq9wzKavfSYSnPyntsLOk8FpOkE"

var parametersForRequest: [String: String] = {
    var parameters = [String:String]()

    let nonce = "HEYTHEREBL1MPYBOY"
    let timeStamp = "1484496492"

    parameters["oauth_consumer_key"] = consumerKey
    parameters["oauth_signature_method"] = "HMAC-SHA1"
    parameters["oauth_timestamp"] = timeStamp
    parameters["oauth_nonce"] = nonce
    parameters["oauth_version"] = "1.0"
    return parameters
}()

var parametersForAuth: [String: String] = {
    var parameters = [String:String]()

    let nonce = "FLY1NGTHROUGHTHESKYSOFANCYFREE"
    let timeStamp = "1484496900"

    parameters["oauth_consumer_key"] = consumerKey
    parameters["oauth_nonce"] = nonce
    parameters["oauth_signature_method"] = "HMAC-SHA1"
    parameters["oauth_timestamp"] = timeStamp
    parameters["oauth_token"] = oAuthToken
    parameters["oauth_version"] = "1.0"
    parameters["oauth_verifier"] = oAuthTokenVerifier

    return parameters
}()

#if os(Linux)
    extension CredentialsTwitterTests {
        static var allTests : [(String, (CredentialsTwitterTests) -> () throws -> Void)] {
            return [
                ("testSecretStringForRequest", testSecretStringForRequest),
                ("testOAuthAuthorizationStringForRequest", testOAuthAuthorizationStringForRequest),
                ("testSecretStringForAuth", testSecretStringForAuth),
                ("testOAuthAuthorizationStringForAuth", testOAuthAuthorizationStringForAuth),
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
        XCTAssertNotNil(signature)
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
        XCTAssertNotNil(signature)
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
}
