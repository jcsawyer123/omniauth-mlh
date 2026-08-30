# frozen_string_literal: true

require 'spec_helper'

RSpec.describe OmniAuth::Strategies::MLH do
  let(:strategy) { described_class.new(app, 'client_id', 'client_secret') }

  let(:app) { ->(_env) { [200, {}, ['Hello.']] } }
  let(:access_token) { instance_double(OAuth2::AccessToken, options: {}) }

  before do
    allow(strategy).to receive(:access_token).and_return(access_token)
  end

  describe 'client options' do
    it 'uses the current MLH OAuth authorize and token endpoints' do
      expect(strategy.options.client_options.authorize_url).to eq('/oauth/authorize')
      expect(strategy.options.client_options.token_url).to eq('https://api.mlh.com/v4/oauth/token')
    end
  end

  shared_context 'with oauth response' do |response_data|
    let(:oauth_response) do
      instance_double(OAuth2::Response,
                      body: response_data.to_json,
                      parsed: response_data)
    end
    before do
      allow(access_token).to receive(:get)
        .with('https://api.mlh.com/v4/users/me')
        .and_return(oauth_response)
    end
  end

  describe '#data' do
    context 'with expandable fields' do
      let(:response) do
        instance_double(OAuth2::Response, body: {}.to_json, parsed: {})
      end
      let(:expand_url) { 'https://api.mlh.com/v4/users/me?expand[]=profile&expand[]=education' }

      before do
        allow(strategy).to receive(:options).and_return(expand_fields: ['profile', 'education'])
        allow(access_token).to receive(:get).with(expand_url).and_return(response)
      end

      it 'constructs the correct URL with expand parameters' do
        strategy.data

        expect(access_token).to have_received(:get).with(expand_url)
      end

      it 'returns an empty hash for empty response' do
        expect(strategy.data).to eq({})
      end
    end

    context 'with v4 API nested profile data' do
      include_context 'with oauth response', {
        'id' => 'test-id',
        'first_name' => 'Jane',
        'profile' => {
          'age' => 22,
          'gender' => 'Female'
        }
      }

      it 'correctly parses nested profile data' do
        result = strategy.data

        expect(result).to be_a(Hash)
        expect(result[:profile]).to eq({ age: 22, gender: 'Female' })
      end
    end

    context 'with v4 API empty response' do
      include_context 'with oauth response', {}

      it 'returns an empty hash for empty data' do
        expect(strategy.data).to eq({})
      end
    end

    context 'with a custom api_site client option' do
      let(:custom_strategy) do
        described_class.new(app, 'client_id', 'client_secret',
                            client_options: { api_site: 'https://api.mlh.test' })
      end

      let(:response) do
        instance_double(OAuth2::Response, body: { 'id' => 'core-user-1' }.to_json)
      end

      before do
        allow(custom_strategy).to receive(:access_token).and_return(access_token)
      end

      it 'fetches user data from the configured API base' do
        expect(access_token).to receive(:get)
          .with('https://api.mlh.test/v4/users/me')
          .and_return(response)

        expect(custom_strategy.data[:id]).to eq('core-user-1')
      end
    end

    context 'with v4 API complex data structures' do
      include_context 'with oauth response', {
        'id' => 'test-id',
        'education' => [{
          'school' => {
            'name' => 'Test University',
            'location' => 'Test City'
          },
          'graduation_year' => 2024
        }],
        'social_profiles' => [
          { 'platform' => 'github', 'url' => 'https://github.com' },
          'https://twitter.com'
        ],
        'professional_experience' => [{
          'company' => 'Tech Corp',
          'positions' => [
            { 'title' => 'Engineer', 'years' => [2022, 2023] }
          ]
        }]
      }

      it 'correctly processes complex nested structures' do
        result = strategy.data

        expect(result).to be_a(Hash)
        expect(result[:education].first[:school]).to eq({ name: 'Test University', location: 'Test City' })
        expect(result[:social_profiles]).to eq([{ platform: 'github', url: 'https://github.com' }, 'https://twitter.com'])
        expect(result[:professional_experience].first[:positions].first[:years]).to eq([2022, 2023])
      end
    end

    context 'with v4 API nil and empty values' do
      include_context 'with oauth response', {
        'id' => 'test-id',
        'first_name' => 'Jane',
        'last_name' => nil,
        'profile' => {
          'age' => 22,
          'gender' => nil,
          'location' => {
            'city' => nil,
            'country' => 'USA'
          }
        },
        'education' => nil,
        'social_profiles' => {
          'github' => {},
          'linkedin' => {}
        }
      }

      it 'handles nil values correctly' do
        result = strategy.data

        expect(result[:last_name]).to be_nil
        expect(result[:profile][:gender]).to be_nil
        expect(result[:profile][:location]).to eq({ city: nil, country: 'USA' })
        expect(result[:education]).to be_nil
      end

      it 'handles empty hash structures' do
        result = strategy.data

        expect(result[:social_profiles]).to eq({ github: {}, linkedin: {} })
      end
    end

    context 'with API error' do
      context 'with OAuth2::Error' do
        let(:error_response) do
          instance_double(OAuth2::Response, status: 500, headers: {},
                                          body: '{"error": "server_error"}')
        end

        before do
          allow(access_token).to receive(:get).and_raise(OAuth2::Error.new(error_response))
        end

        it 'returns empty payload for OAuth2 errors' do
          expect(strategy.data).to eq({})
        end
      end

      context 'with malformed JSON' do
        before do
          allow(access_token).to receive(:get)
            .and_return(instance_double(OAuth2::Response, body: '<html>not json</html>'))
        end

        it 'returns empty payload for JSON parse failures' do
          expect(strategy.data).to eq({})
        end
      end

      context 'with unexpected error' do
        let(:unexpected_error_class) { Class.new(StandardError) }

        before do
          allow(access_token).to receive(:get).and_raise(unexpected_error_class, 'boom')
        end

        it 'propagates unexpected errors' do
          expect { strategy.data }.to raise_error(unexpected_error_class)
        end
      end
    end
  end

  describe '#auth_hash' do
    let(:strategy) do
      described_class.new(app, 'client_id', 'client_secret', persist_credentials: false)
    end

    before do
      allow(strategy).to receive(:data).and_return(id: 'core-user-1')
    end

    it 'omits bearer credentials when persistence is disabled' do
      expect(strategy.auth_hash['credentials']).to eq(
        'token' => '',
        'refresh_token' => nil,
        'secret' => '',
        'expires' => false
      )
    end
  end

  describe '#uid' do
    context 'with valid data' do
      it 'returns the id from the data hash' do
        allow(strategy).to receive(:data).and_return({ id: 'test-123' })
        expect(strategy.uid).to eq('test-123')
      end
    end

    context 'with missing id' do
      it 'returns nil when id is not present' do
        allow(strategy).to receive(:data).and_return({})
        expect(strategy.uid).to be_nil
      end
    end
  end

  describe '#info' do
    let(:user_data) do
      {
        first_name: 'Jane',
        last_name: 'Hacker',
        email: 'jane@example.com',
        roles: ['hacker']
      }
    end

    before do
      allow(strategy).to receive(:data).and_return(user_data)
    end

    it 'includes basic user information' do
      expect(strategy.info).to include(
        first_name: 'Jane',
        last_name: 'Hacker',
        email: 'jane@example.com'
      )
    end

    it 'includes user roles' do
      expect(strategy.info[:roles]).to eq(['hacker'])
    end
  end

  describe 'PKCE authorization' do
    before { OmniAuth.config.test_mode = true }

    after { OmniAuth.config.test_mode = false }

    it 'uses S256 by default and sends the verifier only in token params' do
      params = strategy.authorize_params
      verifier = strategy.options.pkce_verifier

      expect(params[:code_challenge]).to be_present
      expect(params[:code_challenge_method]).to eq('S256')
      expect(params).not_to have_key(:code_verifier)
      expect(verifier).to be_present
      expect(strategy.token_params[:code_verifier]).to eq(verifier)
    end

    it 'can be disabled via the pkce option' do
      disabled_strategy = described_class.new(app, 'client_id', 'client_secret', pkce: false)

      expect(disabled_strategy.authorize_params).not_to include(:code_challenge, :code_challenge_method)
      expect(disabled_strategy.token_params).not_to have_key(:code_verifier)
    end
  end
end
