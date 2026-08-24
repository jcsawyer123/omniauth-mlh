# frozen_string_literal: true

require 'omniauth-oauth2'
require 'ostruct'

module OmniAuth
  module Strategies
    # MLH OAuth2 Strategy
    #
    # @example Basic Usage
    #   use OmniAuth::Builder do
    #     provider :mlh, ENV['MLH_KEY'], ENV['MLH_SECRET']
    #   end
    #
    # @example With Expandable Fields
    #   use OmniAuth::Builder do
    #     provider :mlh, ENV['MLH_KEY'], ENV['MLH_SECRET'],
    #              expand_fields: ['education', 'professional_experience']
    #   end
    #
    # @example With Refresh Tokens (offline access)
    #   use OmniAuth::Builder do
    #     provider :mlh, ENV['MLH_KEY'], ENV['MLH_SECRET'],
    #              scope: 'user:read:profile offline_access'
    #   end
    #
    # When offline_access scope is requested, the strategy will include
    # refresh_token in the credentials hash if provided by the server.
    class MLH < OmniAuth::Strategies::OAuth2 # :nodoc:
      option :name, :mlh

      option :client_options, {
        site: 'https://www.mlh.com',
        authorize_url: '/oauth/authorize',
        token_url: 'https://api.mlh.com/v4/oauth/token',
        # Base for the OAuth2 API (user info). Override when the API lives on a
        # different origin than the default production MyMLH API.
        api_site: 'https://api.mlh.com',
        auth_scheme: :request_body # Change from basic auth to request body
      }

      # Enable PKCE (S256) by default; override with pkce: false for clients that cannot use it
      option :pkce, true

      # When false, provider tokens are blanked in the auth hash before it
      # reaches the host application. Deployments that never call the MLH API
      # on the user's behalf (or proxy through another service) use this to
      # avoid storing bearer material at all. Defaults to true so existing
      # consumers keep receiving working credentials.
      option :persist_credentials, true

      # Support expandable fields through options
      option :expand_fields, []

      uid { data[:id] }

      info do
        {
          # Basic fields
          id: data[:id],
          created_at: data[:created_at],
          updated_at: data[:updated_at],
          first_name: data[:first_name],
          last_name: data[:last_name],
          email: data[:email],
          phone_number: data[:phone_number],
          roles: data[:roles],

          # Expandable fields
          profile: data[:profile],
          address: data[:address],
          social_profiles: data[:social_profiles],
          professional_experience: data[:professional_experience],
          education: data[:education],
          identifiers: data[:identifiers]
        }
      end

      def data
        @data ||= fetch_and_process_data.compact
      rescue ::OAuth2::Error, JSON::ParserError => e
        OmniAuth.logger.warn("OmniAuth MLH: failed to load user data (#{e.class})")
        {}
      end

      private

      def fetch_and_process_data
        response = access_token.get(build_api_url)
        data = JSON.parse(response.body, symbolize_names: true)
        return {} unless data.is_a?(Hash)

        symbolize_nested_arrays(data)
      end

      # omniauth-oauth2 builds this from the access token; when the host asked
      # us not to persist credentials we hand back a shaped-but-empty copy so
      # downstream persistence stores nothing sensitive.
      def credentials
        return super if options.persist_credentials

        OmniAuth::AuthHash.new(
          token: "",
          refresh_token: nil,
          secret: "",
          expires: false
        )
      end

      def build_api_url
        base = (options.dig(:client_options, :api_site) || 'https://api.mlh.com').to_s.chomp('/')
        url = "#{base}/v4/users/me"
        expand_fields = options[:expand_fields] || []
        return url if expand_fields.empty?

        expand_query = expand_fields.map { |f| "expand[]=#{f}" }.join('&')
        "#{url}?#{expand_query}"
      end

      def symbolize_nested_arrays(hash)
        hash.transform_values do |value|
          case value
          when Hash
            symbolize_nested_arrays(value)
          when Array
            value.map { |item| item.is_a?(Hash) ? symbolize_nested_arrays(item) : item }
          else
            value
          end
        end
      end
    end
  end
end

OmniAuth.config.add_camelization 'mlh', 'MLH'
OmniAuth.config.allowed_request_methods = [:post, :get]
OmniAuth.config.silence_get_warning = true
