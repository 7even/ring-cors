(ns ring.middleware.cors-test
  (:require [clojure.test :refer :all]
            [ring.middleware.cors :refer :all]))

(deftest test-allow-request?
  (testing "with empty vector"
    (is (not (allow-request? {:headers {"origin" "http://eample.com"}}
                             {:access-control-allow-origin []}))))
  (testing "with one regular expression"
    (are [origin expected]
      (is (= expected
             (allow-request?
              {:headers {"origin" origin}
               :request-method :get}
              {:access-control-allow-origin [#"http://(.*\.)?burningswell.com"]
               :access-control-allow-methods #{:get :put :post}})))
      nil false
      "" false
      "http://example.com" false
      "http://burningswell.com" true))
  (testing "with multiple regular expressions"
    (are [origin expected]
      (is (= expected
             (allow-request?
              {:headers {"origin" origin}
               :request-method :get}
              {:access-control-allow-origin
               [#"http://(.*\.)?burningswell.com"
                #"http://example.com"]
               :access-control-allow-methods #{:get :put :post}})))
      nil false
      "" false
      "http://example.com" true
      "http://burningswell.com" true
      "http://api.burningswell.com" true
      "http://dev.burningswell.com" true)))

(def handler
  (wrap-cors (fn [_] {})
             :access-control-allow-origin #"http://example.com"
             :access-control-allow-headers #{:accept :content-type}
             :access-control-allow-methods #{:get :put :post}))

(def async-handler
  (wrap-cors (fn [_ respond _] (respond {}))
             :access-control-allow-origin #"http://example.com"
             :access-control-allow-headers #{:accept :content-type}
             :access-control-allow-methods #{:get :put :post}))

(deftest test-preflight
  (testing "whitelist concrete headers"
    (let [headers {"origin" "http://example.com"
                   "access-control-request-method" "POST"
                   "access-control-request-headers" "Accept, Content-Type"}]
      (is (= {:status 200,
              :headers {"Access-Control-Allow-Origin" "http://example.com"
                        "Access-Control-Allow-Headers" "Accept, Content-Type"
                        "Access-Control-Allow-Methods" "GET, POST, PUT"}
              :body "preflight complete"}
             (handler {:request-method :options
                       :uri "/"
                       :headers headers})))))

  (testing "whitelist any headers"
    (is (= {:status 200,
            :headers {"Access-Control-Allow-Origin" "http://example.com"
                      "Access-Control-Allow-Headers" "X-Bar, X-Foo"
                      "Access-Control-Allow-Methods" "GET, POST, PUT"}
            :body "preflight complete"}
           ((wrap-cors (fn [_] {})
                       :access-control-allow-origin #"http://example.com"
                       :access-control-allow-methods #{:get :put :post})
            {:request-method :options
             :uri "/"
             :headers {"origin" "http://example.com"
                       "access-control-request-method" "POST"
                       "access-control-request-headers" "x-foo, x-bar"}}))))

  (testing "whitelist headers ignore case"
    (is (= (handler {:request-method :options
                     :uri "/"
                     :headers {"origin" "http://example.com"
                               "access-control-request-method" "POST"
                               "access-control-request-headers"
                               "ACCEPT, CONTENT-TYPE"}})
           {:status 200
            :headers {"Access-Control-Allow-Origin" "http://example.com"
                      "Access-Control-Allow-Headers" "Accept, Content-Type"
                      "Access-Control-Allow-Methods" "GET, POST, PUT"}
            :body "preflight complete"})))

  (testing "method not allowed"
    (is (empty? (handler
                 {:request-method :options
                  :uri "/"
                  :headers {"origin" "http://example.com"
                            "access-control-request-method" "DELETE"}}))))

  (testing "header not allowed"
    (let [headers {"origin" "http://example.com"
                   "access-control-request-method" "GET"
                   "access-control-request-headers" "x-another-custom-header"}]
      (is (empty? (handler
                   {:request-method :options
                    :uri "/"
                    :headers headers}))))))

(deftest test-preflight-async
  (testing "whitelist concrete headers"
    (let [headers {"origin" "http://example.com"
                   "access-control-request-method" "POST"
                   "access-control-request-headers" "Accept, Content-Type"}
          response (promise)
          exception (promise)]
      (async-handler {:request-method :options
                      :uri "/"
                      :headers headers}
                     response
                     exception)
      (is (= @response
             {:status 200
              :headers {"Access-Control-Allow-Origin" "http://example.com"
                        "Access-Control-Allow-Headers" "Accept, Content-Type"
                        "Access-Control-Allow-Methods" "GET, POST, PUT"}
              :body "preflight complete"}))
      (is (not (realized? exception)))))

  (testing "whitelist any headers"
    (let [handler (wrap-cors (fn [_ respond _] (respond {}))
                             :access-control-allow-origin #"http://example.com"
                             :access-control-allow-methods #{:get :put :post})
          response (promise)
          exception (promise)]
      (handler {:request-method :options
                :uri "/"
                :headers {"origin" "http://example.com"
                          "access-control-request-method" "POST"
                          "access-control-request-headers" "x-foo, x-bar"}}
               response
               exception)
      (is (= @response
             {:status 200
              :headers {"Access-Control-Allow-Origin" "http://example.com"
                        "Access-Control-Allow-Headers" "X-Bar, X-Foo"
                        "Access-Control-Allow-Methods" "GET, POST, PUT"}
              :body "preflight complete"}))
      (is (not (realized? exception)))))

  (testing "whitelist headers ignore case"
    (let [headers {"origin" "http://example.com"
                   "access-control-request-method" "POST"
                   "access-control-request-headers"
                   "ACCEPT, CONTENT-TYPE"}
          response (promise)
          exception (promise)]
      (async-handler {:request-method :options
                      :uri "/"
                      :headers headers}
                     response
                     exception)
      (is (= @response
             {:status 200
              :headers {"Access-Control-Allow-Origin" "http://example.com"
                        "Access-Control-Allow-Headers" "Accept, Content-Type"
                        "Access-Control-Allow-Methods" "GET, POST, PUT"}
              :body "preflight complete"}))
      (is (not (realized? exception)))))

  (testing "method not allowed"
    (let [response (promise)
          exception (promise)]
      (async-handler {:request-method :options
                      :uri "/"
                      :headers {"origin" "http://example.com"
                                "access-control-request-method" "DELETE"}}
                     response
                     exception)
      (is (empty? @response))
      (is (not (realized? exception)))))

  (testing "header not allowed"
    (let [headers {"origin" "http://example.com"
                   "access-control-request-method" "GET"
                   "access-control-request-headers" "x-another-custom-header"}
          response (promise)
          exception (promise)]
      (async-handler {:request-method :options
                      :uri "/"
                      :headers headers}
                     response
                     exception)
      (is (empty? @response))
      (is (not (realized? exception))))))

(deftest test-preflight-header-subset
  (is (= (handler {:request-method :options
                   :uri "/"
                   :headers {"origin" "http://example.com"
                             "access-control-request-method" "POST"
                             "access-control-request-headers" "Accept"}})
         {:status 200
          :headers {"Access-Control-Allow-Origin" "http://example.com"
                    "Access-Control-Allow-Headers" "Accept, Content-Type"
                    "Access-Control-Allow-Methods" "GET, POST, PUT"}
          :body "preflight complete"})))

(deftest test-preflight-header-subset-async
  (let [response (promise)
        exception (promise)]
    (async-handler {:request-method :options
                    :uri "/"
                    :headers {"origin" "http://example.com"
                              "access-control-request-method" "POST"
                              "access-control-request-headers" "Accept"}}
                   response
                   exception)
    (is (= @response
           {:status 200
            :headers {"Access-Control-Allow-Origin" "http://example.com"
                      "Access-Control-Allow-Headers" "Accept, Content-Type"
                      "Access-Control-Allow-Methods" "GET, POST, PUT"}
            :body "preflight complete"}))
    (is (not (realized? exception)))))

(deftest test-cors
  (testing "success"
    (is (= {:headers {"Access-Control-Allow-Methods" "GET, POST, PUT",
                      "Access-Control-Allow-Origin" "http://example.com"}}
           (handler {:request-method :post
                     :uri "/"
                     :headers {"origin" "http://example.com"}}))))
  (testing "failure"
    (is (empty? (handler {:request-method :get
                          :uri "/"
                          :headers {"origin" "http://foo.com"}})))))

(deftest test-cors-async
  (testing "success"
    (let [response (promise)
          exception (promise)]
      (async-handler {:request-method :post
                      :uri "/"
                      :headers {"origin" "http://example.com"}}
                     response
                     exception)
      (is (= @response
             {:headers {"Access-Control-Allow-Methods" "GET, POST, PUT",
                        "Access-Control-Allow-Origin" "http://example.com"}}))
      (is (not (realized? exception)))))
  (testing "failure"
    (let [response (promise)
          exception (promise)]
      (async-handler {:request-method :get
                      :uri "/"
                      :headers {"origin" "http://foo.com"}}
                     response
                     exception)
      (is (empty? @response))
      (is (not (realized? exception))))))

(deftest test-no-cors-header-when-handler-returns-nil
  (is (nil? ((wrap-cors (fn [_] nil)
                        :access-control-allow-origin #".*example.com"
                        :access-control-allow-methods [:get])
             {:request-method
              :get :uri "/"
              :headers {"origin" "http://example.com"}}))))

(deftest test-no-cors-header-when-handler-returns-nil-async
  (let [handler (wrap-cors (fn [_ respond _] (respond nil))
                           :access-control-allow-origin #".*example.com"
                           :access-control-allow-methods [:get])
        response (promise)
        exception (promise)]
    (handler {:request-method
              :get :uri "/"
              :headers {"origin" "http://example.com"}}
             response
             exception)
    (is (nil? @response))
    (is (not (realized? exception)))))

(deftest test-options-without-cors-header
  (is (empty? ((wrap-cors
                (fn [_] {})
                :access-control-allow-origin #".*example.com")
               {:request-method :options :uri "/"}))))

(deftest test-options-without-cors-header-async
  (let [handler (wrap-cors
                 (fn [_ respond _] (respond {}))
                 :access-control-allow-origin #".*example.com")
        response (promise)
        exception (promise)]
    (handler {:request-method :options :uri "/"}
             response
             exception)
    (is (empty? @response))
    (is (not (realized? exception)))))

(deftest test-method-not-allowed
  (is (empty? ((wrap-cors
                (fn [_] {})
                :access-control-allow-origin #".*"
                :access-control-allow-methods [:get :post :patch :put :delete])
               {:request-method :options
                :headers {"origin" "http://foo.com"}
                :uri "/"}))))

(deftest test-method-not-allowed-async
  (let [allowed-methods [:get :post :patch :put :delete]
        handler (wrap-cors (fn [_ respond _] (respond {}))
                           :access-control-allow-origin #".*"
                           :access-control-allow-methods allowed-methods)
        response (promise)
        exception (promise)]
    (handler {:request-method :options
              :headers {"origin" "http://foo.com"}
              :uri "/"}
             response
             exception)
    (is (empty? @response))
    (is (not (realized? exception)))))

(deftest additional-headers
  (let [response ((wrap-cors (fn [_] {:status 200})
                             :access-control-allow-credentials "true"
                             :access-control-allow-origin #".*"
                             :access-control-allow-methods [:get]
                             :access-control-expose-headers "Etag")
                  {:request-method :get
                   :uri "/"
                   :headers {"origin" "http://example.com"}})]
    (is (= {:status 200
            :headers
            {"Access-Control-Allow-Credentials" "true"
             "Access-Control-Allow-Methods" "GET"
             "Access-Control-Allow-Origin" "http://example.com"
             "Access-Control-Expose-Headers" "Etag"}}
           response))))

(deftest additional-headers-async
  (let [handler (wrap-cors (fn [_ respond _] (respond {:status 200}))
                           :access-control-allow-credentials "true"
                           :access-control-allow-origin #".*"
                           :access-control-allow-methods [:get]
                           :access-control-expose-headers "Etag")
        response (promise)
        exception (promise)]
    (handler {:request-method :get
              :uri "/"
              :headers {"origin" "http://example.com"}}
             response
             exception)
    (is (= @response
           {:status 200
            :headers
            {"Access-Control-Allow-Credentials" "true"
             "Access-Control-Allow-Methods" "GET"
             "Access-Control-Allow-Origin" "http://example.com"
             "Access-Control-Expose-Headers" "Etag"}}))))

(deftest test-parse-headers
  (are [headers expected]
    (= (parse-headers headers) expected)
    nil #{}
    "" #{}
    "accept" #{"accept"}
    "Accept" #{"accept"}
    "Accept, Content-Type" #{"accept" "content-type"}
    " Accept ,  Content-Type " #{"accept" "content-type"}))

(deftest test-preflight-headers?
  (testing "Acceptable allowed-headers"
    (let [headers {"Access-Control-Allow-Headers" "Accept, Content-Type"}
          request {:request-method :get
                   :uri "/"
                   :headers headers}]
      (are [allowed-headers]
          (is (true? (allow-preflight-headers? request allowed-headers)))
        [:accept :content-type]
        [:Accept :Content-Type]
        ["accept" "content-type"]
        ["Accept" "Content-Type"]
        ["  cOntenT-typE " " acCePt"]))))

(deftest test-dynamic-allow-origin
  (testing "Testing an allow-origin with a callback function
            for dynamic checks, where it returns true (allowed)"
    (let [response ((wrap-cors
                     (fn [_] {})
                     :access-control-allow-origin
                      (fn my-callback [req] true)
                     :access-control-allow-methods
                      [:get :post :patch :put :delete])
                    {:request-method :get
                     :headers        {"origin" "http://foo.com"}
                     :uri            "/"})]
      (is (= {:headers
              {"Access-Control-Allow-Methods" "DELETE, GET, PATCH, POST, PUT"
               "Access-Control-Allow-Origin" "http://foo.com"}}
             response))))
  (testing "Testing an allow-origin with a callback function for dynamic checks,
           where it returns false (not allowed)"
    (let [response ((wrap-cors
                     (fn [_] {})
                     :access-control-allow-origin
                      (fn my-callback [req] false)
                     :access-control-allow-methods
                      [:get :post :patch :put :delete])
                    {:request-method :get
                     :headers        {"origin" "http://foo.com"}
                     :uri            "/"})]
      (is (empty? response)))))

(deftest test-dynamic-allow-origin-async
  (testing "Testing an allow-origin with a callback function
            for dynamic checks, where it returns true (allowed)"
    (let [handler (wrap-cors
                   (fn [_ respond _] (respond {}))
                   :access-control-allow-origin
                   (fn my-callback [req] true)
                   :access-control-allow-methods
                   [:get :post :patch :put :delete])
          response (promise)
          exception (promise)]
      (handler {:request-method :get
                :headers        {"origin" "http://foo.com"}
                :uri            "/"}
               response
               exception)
      (is (= @response
             {:headers
              {"Access-Control-Allow-Methods" "DELETE, GET, PATCH, POST, PUT"
               "Access-Control-Allow-Origin" "http://foo.com"}}))
      (is (not (realized? exception)))))
  (testing "Testing an allow-origin with a callback function for dynamic checks,
           where it returns false (not allowed)"
    (let [handler (wrap-cors
                   (fn [_ respond _] (respond {}))
                   :access-control-allow-origin
                   (fn my-callback [req] false)
                   :access-control-allow-methods
                   [:get :post :patch :put :delete])
          response (promise)
          exception (promise)]
      (handler {:request-method :get
                :headers        {"origin" "http://foo.com"}
                :uri            "/"}
               response
               exception)
      (is (empty? @response))
      (is (not (realized? exception))))))
