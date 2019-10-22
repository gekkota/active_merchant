 require 'rexml/document'
require 'digest/sha1'

module ActiveMerchant
  module Billing
    # Realex us the leading CC gateway in Ireland
    # see http://www.realexpayments.com
    # Contributed by John Ward (john@ward.name)
    # see http://thinedgeofthewedge.blogspot.com
    #
    # Realex works using the following
    # login - The unique id of the merchant
    # password - The secret is used to digitally sign the request
    # account - This is an optional third part of the authentication process
    # and is used if the merchant wishes do distuinguish cc traffic from the different sources
    # by using a different account. This must be created in advance
    #
    # the Realex team decided to make the orderid unique per request,
    # so if validation fails you can not correct and resend using the
    # same order id
    class RealexGateway < Gateway
      # URL = 'https://api.sandbox.realexpayments.com/epage-remote.cgi'
      # 'https://api.realexpayments.com/epage-remote.cgi'
       URL = 'https://epage.payandshop.com/epage-remote.cgi'
       # 'https://api.sandbox.realexpayments.com/epage-remote.cgi'
      # 'https://api.realexpayments.com/epage-remote.cgi'
      URL_3D = 'https://epage.payandshop.com/epage-3dsecure.cgi'
      CARD_MAPPING = {
        'master'            => 'MC',
        'visa'              => 'VISA',
        'american_express'  => 'AMEX',
        'diners_club'       => 'DINERS',
        'switch'            => 'SWITCH',
        'solo'              => 'SWITCH',
        'laser'             => 'LASER'
      }

      self.money_format = :cents
      self.default_currency = 'EUR'
      self.supported_cardtypes = [ :visa, :master, :american_express, :diners_club, :switch, :solo, :laser ]
      self.supported_countries = [ 'IE', 'GB' ]
      self.homepage_url = 'http://www.realexpayments.com/'
      self.display_name = 'Realex'

      SUCCESS, DECLINED          = "Successful", "Declined"
      BANK_ERROR = REALEX_ERROR  = "Gateway is in maintenance. Please try again later."
      ERROR = CLIENT_DEACTIVATED = "Gateway Error"
      NO_DCC="NO DCC"

      def initialize(options = {})
        requires!(options, :login, :password)
        @options = options
        super
      end

      def refund(money, options={})
        requires!(options, :order_id)
        request = build_refund_request(money, options)
        response = commit(request)
      end

      def purchase(money, credit_card, options = {})
        requires!(options, :order_id)
        dcc = options[:use_dcc]==true

        if dcc
        request = build_purchase_or_authorization_request(:purchase, money, credit_card, options, "realvault-dccrate", {} )
        response = commit(request)
        puts 'DCC'
        puts "request: #{request}"
        puts "response: #{response}"
        # raise response.inspect
        end
        if response.blank? || response.message=="NO DCC" || dcc == false
        dcc_hash= {:rate=>1 , :currency=>"GBP" , :amount=>money.cents}
        else
        dcc_hash = {:rate=>response.params['dccinfo_cardholderrate'] , :currency=>response.params['dccinfo_cardholdercurrency'] , :amount=>response.params['dccinfo_cardholderamount']}
        end
        #this is an actual payment
        request_b = build_purchase_or_authorization_request(:purchase, money, credit_card, options, "auth",  dcc_hash)
          # raise request_b.inspect

        puts 'Normal'
        puts "request: #{request_b}"

        response = commit(request_b)
        puts "response: #{response.inspect}"
        response
        #raise response.inspect
      end


      def default_dcc_hash(money)
      {:rate=>1 , :currency=>"GBP" , :amount=>money.cents}
      end

      def attempt_purchase(money, credit_card, options = {})
        requires!(options, :order_id)
        dcc = options[:use_dcc]==true
        request = build_purchase_or_authorization_request(:purchase, money, credit_card, options, "realvault-dccrate", {} )
        response = commit(request, URL_3D)

        #options[:use_dcc] = true

        if response.message=="NO DCC" || dcc == false
        dcc_hash= default_dcc_hash(money)
        else
        dcc_hash = {:rate=>response.params['dccinfo_cardholderrate'] , :currency=>response.params['dccinfo_cardholdercurrency'] , :amount=>response.params['dccinfo_cardholderamount']}
        end

        request = build_3d_request(money, credit_card, options, dcc_hash)
        response = commit(request, URL_3D)
        #raise "#{response.inspect} ------------------------------- #{request.inspect}"
        response.md = md_string_from_hash(dcc_hash)  #if dcc && options[:md]

         if !response.success? &&  !url_for_3d(response) && not_enrolled_in_3d?(response)
            options[:eci] = 1#credit_card.type == :visa ? 6 : 1
            response = auth_3d_purchase(money, credit_card, options, dcc_hash)
            #At this point it may still be rejected as a Referral B, or standard failures.
            # response.referral_b?
         end
         # raise response.to_yaml
         response
      end

     def md_string_from_hash(dcc_hash)
        md_encrypt(dcc_hash.map{|k,v| "#{k}=#{v}"}.join('&'))
      end

      def hash_from_md_string(md_string)
        Rack::Utils.parse_nested_query(md_decrypt(md_string))
      end

      def auth_3d_purchase(money, credit_card, options, dcc_hash=nil)
        requires!(options, :order_id)
        if dcc_hash.nil?
        dcc_hash = hash_from_md_string(options[:md]) if options[:md] && !options[:md].blank?

        end
        puts dcc_hash
        #this is a purchase
        request = build_3d_purchase_or_authorization_request(money, credit_card, options, dcc_hash)
        puts request.to_yaml
        response = commit(request, URL_3D)
      end

      private

      def commit(request, url = URL)
        puts request
        response = parse(ssl_post(url, request))

        final_response = Response.new(response[:result] == "00", message_from(response), response,
          :test => response[:message] =~ /\[ test system \]/,
          :authorization => response[:authcode],
          :cvv_result => response[:cvnresult],
          :rate=>response[:cardholderrate],
          :currency=>response[:cardholdercurrency],
          :amount=>response[:cardholderamount],
          :three_d_secure => response[:enrolled] == 'Y',
          :pareq => response[:pareq],
          :md => response["MD"],
          :acs_url => response[:url],
          :eci=>response[:threedsecure_eci],
          :xid=>response[:threedsecure_xid],
          :cavv=>response[:threedsecure_cavv]
        )
        puts response
        final_response
      end

      def parse(xml)
        response = {}

        xml = REXML::Document.new(xml)
        xml.elements.each('//response/*') do |node|

          if (node.elements.size == 0)
            response[node.name.downcase.to_sym] = normalize(node.text)
          else
            node.elements.each do |childnode|
              name = "#{node.name.downcase}_#{childnode.name.downcase}"
              response[name.to_sym] = normalize(childnode.text)
            end
          end

        end unless xml.root.nil?

        response
      end

      def build_3d_request(money, credit_card, options, dcc)
        timestamp = Time.now.strftime('%Y%m%d%H%M%S')
        mode = options[:mode].blank? ? 'realvault-3ds-verifyenrolled' : '3ds-verifysig'


        xml = Builder::XmlMarkup.new :indent => 2
        xml.tag! 'request', 'timestamp' => timestamp, 'type'=>mode do
        xml.tag! 'merchantid', @options[:login]
        xml.tag! 'account', @options[:account]
        xml.tag! 'orderid', options[:order_id]
        xml.tag! 'amount', (money.cents), 'currency' => 'GBP' #dcc[:currency]

        unless mode == "3ds-verifysig"
        xml.tag! 'dccinfo' do
            xml.tag! 'ccp', "fexco"
            xml.tag! 'type', "1"
            if !dcc[:rate].blank?
              xml.tag! 'rate', dcc[:rate]
              xml.tag! 'ratetype', "S"
              xml.tag! 'amount', dcc[:amount], 'currency'=>dcc[:currency]
            end
          end

          if credit_card.class == ActiveMerchant::Billing::CreditCard
          xml.tag! 'card' do
            xml.tag! 'number', credit_card.number
            xml.tag! 'expdate', expiry_date(credit_card)
            xml.tag! 'type', CARD_MAPPING[credit_card.type.to_s]
            xml.tag! 'chname', credit_card.name
            # xml.tag! 'issueno', credit_card.issue_number

            xml.tag! 'cvn' do
              xml.tag! 'number', credit_card.verification_value
              xml.tag! 'presind', credit_card.verification_value? ? 1 : nil
            end
          end
          else


            xml.tag! 'payerref', credit_card[:payer_ref]
            xml.tag! 'paymentmethod', credit_card[:card_ref]

            #type = variable / fixed, sequence = first, subsequent, final
            # xml.tag! 'recurring', 'type='> 'variable', 'sequence'=>credit_card[:sequence] unless mode == 'realvault-3ds-verifyenrolled'

          end
        end

          xml.tag! 'pares', options[:pares] unless options[:pares].blank?

          credit_card = "" if mode == "3ds-verifysig"
          xml.tag! 'sha1hash', shamaker(timestamp,money, options, credit_card)
        end
             #raise xml.inspect
      end

      def build_3d_purchase_or_authorization_request(money, credit_card, options, dcc)
        timestamp = Time.now.strftime('%Y%m%d%H%M%S')

        xml = Builder::XmlMarkup.new :indent => 2
        xml.tag! 'request', 'timestamp' => timestamp, 'type' => 'receipt-in' do

          xml.tag! 'merchantid', @options[:login]
          xml.tag! 'account', @options[:account]

          xml.tag! 'orderid', sanitize_order_id(options[:order_id])
          xml.tag! 'amount', (money.cents), 'currency' => options[:currency] || currency(money)

          #check to see if there has been a card passed through or realvault reference.

          if credit_card.class == ActiveMerchant::Billing::CreditCard
          xml.tag! 'card' do
            xml.tag! 'number', credit_card.number
            xml.tag! 'expdate', expiry_date(credit_card)
            xml.tag! 'type', CARD_MAPPING[credit_card.type.to_s]
            xml.tag! 'chname', credit_card.name
            # xml.tag! 'issueno', credit_card.issue_number

            xml.tag! 'cvn' do
              xml.tag! 'number', credit_card.verification_value
              xml.tag! 'presind', credit_card.verification_value? ? 1 : nil
            end
          end
          else

            xml.tag! 'payerref', credit_card[:payer_ref]
            xml.tag! 'paymentmethod', credit_card[:card_ref]

            #type = variable / fixed, sequence = first, subsequent, final
            # xml.tag! 'recurring',  'type'=> 'variable', 'sequence'=>credit_card[:sequence]

          end
          xml.tag! 'autosettle', 'flag' => 1

          if dcc
            dcc = dcc.stringify_keys

            xml.tag! 'dccinfo' do
              xml.tag! 'ccp', "fexco"
              xml.tag! 'type', "1"
              xml.tag! 'rate', dcc['rate']
              xml.tag! 'ratetype', "S"
              xml.tag! 'amount', dcc['amount'], 'currency'=>dcc['currency']
            end
          end

          xml.tag! 'mpi' do
            xml.tag! 'cavv', options[:cavv]
            xml.tag! 'xid', options[:xid]
            xml.tag! 'eci', options[:eci]
          end


          xml.tag! 'sha1hash', shamaker(timestamp, money, options, credit_card)
          xml.tag! 'comments' do
            xml.tag! 'comment', options[:description], 'id' => 1
            xml.tag! 'comment', 'id' => 2
          end
        end

        xml.target!
        #raise xml.inspect

      end

      def shamaker(timestamp,money, options, credit_card="")
        timestampa = Time.now.strftime('%Y%m%d%H%M%S')
        currency = options[:currency] || currency(money)
        card_hash = credit_card.class == Hash ? credit_card[:payer_ref] : credit_card == "" ? "" : credit_card.number
        card_hash ="#{card_hash}" unless card_hash == ""
        string = "#{timestampa}.#{@options[:login]}.#{sanitize_order_id(options[:order_id])}.#{amount(money)}.#{currency}.#{ card_hash  }"
        puts string
        string = Digest::SHA1.hexdigest(string)
        string += ".#{@options[:password]}"
        puts string
        Digest::SHA1.hexdigest(string)
      end

      def parse_credit_card_number(request)
        xml = REXML::Document.new(request)
        card_number = REXML::XPath.first(xml, '/request/card/number')
        card_number && card_number.text
      end

      def build_refund_request(money, options)
        timestamp = Time.now.strftime('%Y%m%d%H%M%S')

        xml = Builder::XmlMarkup.new :indent => 2
        xml.tag! 'request', 'timestamp' => timestamp, 'type' => 'rebate' do

            xml.tag! 'merchantid', @options[:login]
            xml.tag! 'account', @options[:account]

            xml.tag! 'orderid', options[:order_id]
            xml.tag! 'amount', (money.cents), 'currency' => options[:currency] || currency(money)
            xml.tag! 'pasref', options[:pasref]
            xml.tag! 'authcode', options[:authcode]
            xml.tag! 'autosettle', 'flag' => '1'

            xml.tag! 'refundhash', plainsha1(@options[:refund_password])

            xml.tag! 'dccinfo' do
            xml.tag! 'ccp', "fexco"
            xml.tag! 'type', "1"
              xml.tag! 'rate',  "1"
              xml.tag! 'ratetype', "S"
              xml.tag! 'amount', money.cents, 'currency'=>options[:currency] || currency(money)
          end

            xml.tag! 'sha1hash', shamaker(timestamp,money, options, credit_card)
        end
      end

      def build_purchase_or_authorization_request(action, money, credit_card, options, stage, dcc)
        timestamp = Time.now.strftime('%Y%m%d%H%M%S')
        stage = "receipt-in" if stage == 'auth' &&  credit_card.class != ActiveMerchant::Billing::CreditCard
        xml = Builder::XmlMarkup.new :indent => 2
        xml.tag! 'request', 'timestamp' => timestamp, 'type' => stage do

          xml.tag! 'merchantid', @options[:login]
          xml.tag! 'account', @options[:account]

          xml.tag! 'orderid', sanitize_order_id(options[:order_id])
          xml.tag! 'amount', (money.cents), 'currency' => options[:currency] || currency(money)
          puts credit_card.class
          if credit_card.class == ActiveMerchant::Billing::CreditCard
          xml.tag! 'card' do
            xml.tag! 'number', credit_card.number
            xml.tag! 'expdate', expiry_date(credit_card)
            xml.tag! 'type', CARD_MAPPING[credit_card.type.to_s]
            xml.tag! 'chname', credit_card.name
            # xml.tag! 'issueno', credit_card.issue_number

            xml.tag! 'cvn' do
              xml.tag! 'number', credit_card.verification_value
              xml.tag! 'presind', credit_card.verification_value? ? 1 : nil
            end
          end
          else

            xml.tag! 'payerref', credit_card[:payer_ref]
            xml.tag! 'paymentmethod', credit_card[:card_ref]

            #type = variable / fixed, sequence = first, subsequent, final
            # xml.tag! 'recurring',  'type'=> 'variable', 'sequence'=>credit_card[:sequence]
          end
          xml.tag! 'autosettle', 'flag' => auto_settle_flag(action)
          # if !dcc.blank?

          xml.tag! 'dccinfo' do
            xml.tag! 'ccp', "fexco"
            xml.tag! 'type', "1"
            if stage=="auth" || stage=="receipt-in"
              xml.tag! 'rate', dcc[:rate]
              xml.tag! 'ratetype', "S"
              xml.tag! 'amount', dcc[:amount], currency: dcc[:currency]
            end
          end

        # end
          xml.tag! 'sha1hash', shamaker(timestamp,money, options, credit_card)
          xml.tag! 'comments' do
            xml.tag! 'comment', options[:description], 'id' => 1
            xml.tag! 'comment', 'id' => 2
          end

          billing_address = options[:billing_address] || options[:address] || {}
          shipping_address = options[:shipping_address] || {}

          xml.tag! 'tssinfo' do
            xml.tag! 'address', 'type' => 'billing' do
              xml.tag! 'code', billing_address[:zip]
              xml.tag! 'country', billing_address[:country]
            end

            xml.tag! 'address', 'type' => 'shipping' do
              xml.tag! 'code', shipping_address[:zip]
              xml.tag! 'country', shipping_address[:country]
            end

            # xml.tag! 'custnum', options[:customer]

            # xml.tag! 'prodid', options[:invoice]
            # xml.tag! 'varref'
          end
        end

        xml.target!
           #raise xml.inspect
      end

      def auto_settle_flag(action)
        action == :authorization ? '0' : '1'
      end

      def expiry_date(credit_card)
        "#{format(credit_card.month, :two_digits)}#{format(credit_card.year, :two_digits)}"
      end

      def sha1from(string)
        string = Digest::SHA1.hexdigest(string)
        string += ".#{@options[:password]}"
        puts string
        Digest::SHA1.hexdigest(string)
      end

     def plainsha1(string)
       Digest::SHA1.hexdigest(string)
      end

      def normalize(field)
        case field
        when "true"   then true
        when "false"  then false
        when ""       then nil
        when "null"   then nil
        else field
        end
      end

      def three_d_status(status)
        case status
        when 'Y' then true
        when 'N' then false
        when 'A' then true
        when 'U' then true
        end
      end

      def url_for_3d(response)
        response.params['url']
      end

      def enrolled_in_3d?(response)
        response.params[:result] == '00'
      end

      def not_enrolled_in_3d?(response)
        response.params['result'] == '110'
      end

      def md_encrypt(string)
      blowfish = Crypt::Blowfish.new("A key up to 56 bytes long")
      enc = blowfish.encrypt_string(string)
      mimed = Base64.encode64(enc)
      end

      require 'rubygems'
      require 'crypt/blowfish'
      require 'base64'

      def md_decrypt(string)
      blowfish = Crypt::Blowfish.new("A key up to 56 bytes long")
      enco = Base64.decode64(string)
      blowfish.decrypt_string(enco)
      end

      def referral_b?(response)
        response[:result] == "102" && response[:message] == 'REFERRAL B'
      end

      def message_from(response)
        message = nil
        case response[:result]
        when "00"
          message = SUCCESS
        when "101"
          message = response[:message]
        when "102", "103"
          if referral_b?(response)
            message = 'REF_B'
          else
          message = DECLINED
        end
        when "105"
          message = "NO DCC"
        when /^2[0-9][0-9]/
          message = BANK_ERROR
        when /^3[0-9][0-9]/
          message = REALEX_ERROR
        when /^5[0-9][0-9]/
          message = ERROR
        when "666"
          message = CLIENT_DEACTIVATED
        else
          message = response.inspect
        end
      end

      def sanitize_order_id(order_id)
        order_id.to_s.gsub(/[^a-zA-Z0-9\-_]/, '')
      end
    end
  end
end
