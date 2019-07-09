module ActiveMerchant::Billing

  class RealvaultGateway < RealexGateway
    # 7. on page 24
    URL = 'https://epage.payandshop.com/epage-remote-plugins.cgi'

    # 7.1 (Setup a new Payer)
    # Create a Profile for a payer using payer‐new
    # If the payer exists another one will be stored
    # payer is a hash (see self.test)
    def send_payer(payer, options = {})

      request = build_payer_new_request payer, options
      commit request, URL
    end

    def delete_card(options={})
      requires! options, :payerref, :card_ref
      request = build_card_delete_request(options)
      commit request, URL
    end

    def update_card(card, options )
     requires! options, :payerref, :card_ref
      request = build_card_update_request(card, options)
      commit request, URL
    end

    # 7.2 (Payment method setup)
    # Store the Card details using Card‐New
    # If the card exists another one will be stored
    # card is a ActiveMerchant::Billing::CreditCard
    # options is a hash
    def send_card(card, options)
      requires! options, :order_id
      request = build_card_new_request card, options
      commit request, URL
    end

    # see self.test or send_x methods
    def store!(payer, card, options)
      send_payer_response = send_payer(payer, options)
      send_card_response  = send_card(card, options) if send_payer_response.success?

      { :success? => (send_payer_response.success? && send_card_response.success?),
        :send_payer_response => send_payer_response,
        :send_card_response  => send_card_response }
    end

    # ActiveMerchant::Billing::RealVault.test
    # will store the payer and the card in the test account
    # makes a purchase before as suggested by the doc. to make sure auth is ok
    # works out of the box
    def self.test
      timestamp = Time.new.to_s :number
      currency  = 'GBP'
      firstname = 'John'
      surname   = 'Smith'
      payerref  = timestamp
      orderid   = timestamp

      login = REALEX_LOGIN
      password = REALEX_PASSWORD

      account = 'internet'

      rv = ActiveMerchant::Billing::RealvaultGateway.new({:login => login, :password => password, :account=>account,
                                                   :currency => currency,
                                                   :rebate   => "rebate",

                                                   :gateway  => "Realex"})

      card = ActiveMerchant::Billing::CreditCard.new(
                    :number             => '4263971921001307',
                    :month              => '12',
                    :year               => '2022',
                    :type               => 'visa',
                    :first_name         => firstname,
                    :last_name          => surname,
                    :verification_value => '123')

      payer = { :type      => 'Business',
                :ref       =>  'smithj01',
                :title     => 'Mr',
                :firstname => firstname,
                :surname   => surname,
                :email     => 'jsmith@acme.com',
                :company   => 'Acme Inc',
                :address   => {
                  :line1   => '123 Fake St.',
                  # :line2
                  # :line3
                  :postcode     => '3',
                  :city         => 'Hytown',
                  :county       => 'Dunham',
                    :country      => 'Ireland',
                  :country_code => 'IE'
                },
                :phonenumbers => {
                  :home   => '55555555',
                  :work   => '+35317433923',
                  :fax    => '+35317893248',
                  :mobile => '+353873748392',
                }
              }

      options = {:order_id => orderid,
                 :currency => currency,
                 :payerref => payer[:ref]}

      # rv.purchase Money.new(777), card, options
       #rv.store! payer, card, options
      # rv.send_payer payer, options
      rv.send_card card, options
    end

    private

    def build_card_update_request(card, options)

      timestamp = Time.now.strftime '%Y%m%d%H%M%S' # same as to_s(:number), but not subjected to override
      chname    = "#{card.first_name}#{card.last_name}"
      expdate   = card.year.to_s[2..3] + card.month.to_s
      sha1      = sha1from "#{timestamp}.#{@options[:login]}.#{options[:payerref]}.#{options[:card_ref]}.#{expiry_date(card)}.#{card.number}"
      xml       = Builder::XmlMarkup.new :indent => 2

      xml.tag! :request, :timestamp => timestamp, :type => 'card-update-card' do
        xml.tag! :merchantid, @options[:login]
        xml.tag! :card do
          xml.tag! :ref     , options[:card_ref] #card.type + timestamp[3..14]
          xml.tag! :payerref, options[:payerref]
          xml.tag! :number  , card.number
          xml.tag! :expdate , expiry_date(card)
          xml.tag! :chname  , chname
          xml.tag! :type    , CARD_MAPPING[card.type.to_s]
          xml.tag! :issueno
        end
        xml.tag! :sha1hash, sha1
      end


    end

    def build_card_new_request(card, options)
      action    = 'card-new'
      timestamp = Time.now.strftime '%Y%m%d%H%M%S' # same as to_s(:number), but not subjected to override
      orderid   = sanitize_order_id options[:order_id]
      chname    = "#{card.first_name}#{card.last_name}"
      expdate   = card.year.to_s[2..3] + card.month.to_s

      sha1      = sha1from "#{timestamp}.#{@options[:login]}.#{orderid}...#{options[:payerref]}.#{chname}.#{card.number}"

      xml       = Builder::XmlMarkup.new :indent => 2

      xml.tag! :request, :timestamp => timestamp, :type => action do
        xml.tag! :merchantid, @options[:login]
        xml.tag! :orderid   , orderid
        xml.tag! :card do
          xml.tag! :ref     , "customer_#{orderid}" #card.type + timestamp[3..14]
          xml.tag! :payerref, options[:payerref]
          xml.tag! :number  , card.number
          xml.tag! :expdate , expiry_date(card)
          xml.tag! :chname  , chname
          xml.tag! :type    , CARD_MAPPING[card.type.to_s]
          xml.tag! :issueno
        end
        xml.tag! :sha1hash, sha1
      end

    end


    def build_card_delete_request(options)
      action    = 'card-cancel-card'
      timestamp = Time.now.strftime '%Y%m%d%H%M%S' # same as to_s(:number), but not subjected to override

      sha1      = sha1from "#{timestamp}.#{@options[:login]}.#{options[:payerref]}.#{options[:card_ref]}"

      xml       = Builder::XmlMarkup.new :indent => 2
      xml.tag! :request, :timestamp => timestamp, :type => action do
        xml.tag! :merchantid, @options[:login]

        xml.tag! :card do
          xml.tag! :ref     , options[:card_ref] # customer_#{orderid}"
          xml.tag! :payerref, options[:payerref]
        end
        xml.tag! :sha1hash, sha1
      end

    end


    def build_payer_new_request(payer, options)
      action    = 'payer-new'
      timestamp = Time.now.strftime '%Y%m%d%H%M%S' # same as to_s(:number), but not subjected to override
      orderid   = sanitize_order_id options[:order_id]
      sha1      = sha1from "#{timestamp}.#{@options[:login]}.#{orderid}...#{payer[:ref]}"

      xml       = Builder::XmlMarkup.new :indent => 2

      xml.tag! :request, :timestamp => timestamp, :type => action do

        xml.tag! :merchantid, @options[:login]
        xml.tag! :account   , @options[:account]
        xml.tag! :orderid   , orderid

        xml.tag! :payer, :type => payer[:type], :ref => payer[:ref] do
          [:title, :firstname, :surname, :company].each do |tag|
            xml.tag! tag, payer.send('[]', tag)
          end
          xml.tag! :address do
            address = payer[:address]
            [:line1, :line2, :line3, :city, :county, :postcode].each do |tag|
              xml.tag! tag, address.send('[]', tag)
            end
            xml.tag! :country, address[:country], :code => address[:country_code]
          end
          xml.tag! :phonenumbers do
            phonenumbers = payer[:phonenumbers]
            [:home, :work, :fax, :mobile].each do |tag|
              xml.tag! tag, phonenumbers[tag]
            end
          end
          xml.tag! :email, payer[:email]
          xml.tag! :comments do
            xml.tag! :comment, nil, :id => 1
            xml.tag! :comment, nil, :id => 2
          end
        end
        xml.tag! :sha1hash, sha1
        xml.tag! :comments do
            xml.tag! :comment, nil, :id => 1
            xml.tag! :comment, nil, :id => 2
        end
      end

      xml.target!

    end


  end




end
