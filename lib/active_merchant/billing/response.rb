module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
  
    class Error < StandardError #:nodoc:
    end
  
    class Response
      attr_reader :params
      attr_reader :message
      attr_reader :test
      attr_reader :authorization
      attr_reader :avs_result, :cvv_result, :pareq,  :acs_url
      attr_accessor :md
      attr_reader :xid, :cavv, :eci
      def success?
        @success
      end

      def test?
        @test
      end
      
      def fraud_review?
        @fraud_review
      end

       def three_d_secure?
        @three_d_secure
      end

      def referral_b?
        message == 'REF_B'
      end
      
      def initialize(success, message, params = {}, options = {})
        @success, @message, @params = success, message, params.stringify_keys
        @test = options[:test] || false        
        @authorization = options[:authorization]
        @fraud_review = options[:fraud_review]

        @three_d_secure = options[:three_d_secure]
        @pareq = options[:pareq]
        @md = options[:md]
        @acs_url = options[:acs_url]

        @xid = options[:xid]
        @cavv = options[:cavv]
        @eci = options[:eci]        

      end
    end

    class MultiResponse < Response
      def self.run(use_first_response = false, &block)
        new(use_first_response).tap(&block)
      end

      attr_reader :responses, :primary_response

      def initialize(use_first_response = false)
        @responses = []
        @use_first_response = use_first_response
        @primary_response = nil
      end

      def process(ignore_result=false)
        return unless success?

        response = yield
        self << response

        unless ignore_result
          if(@use_first_response && response.success?)
            @primary_response ||= response
          else
            @primary_response = response
          end
        end
      end

      def <<(response)
        if response.is_a?(MultiResponse)
          response.responses.each { |r| @responses << r }
        else
          @responses << response
        end
      end

      def success?
        (primary_response ? primary_response.success? : true)
      end

      %w(params message test authorization avs_result cvv_result error_code emv_authorization test? fraud_review?).each do |m|
        class_eval %(
          def #{m}
            (@responses.empty? ? nil : primary_response.#{m})
          end
        )
      end
    end
  end
end
