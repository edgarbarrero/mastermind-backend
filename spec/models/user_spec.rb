require 'rails_helper'

RSpec.describe User, type: :model do
  describe 'validations' do
    subject { build(:user) }

    it { should validate_presence_of(:email) }
    it { should validate_uniqueness_of(:email).case_insensitive }
    it { should validate_presence_of(:password).on(:create) }
    it { should validate_length_of(:password).is_at_least(6).on(:create) }
    it { should validate_presence_of(:password_confirmation).on(:create) }

    describe 'email format' do
      it 'is valid with a proper email format' do
        user = build(:user, email: 'valid@example.com')
        expect(user).to be_valid
      end

      it 'is invalid with an improper email format' do
        user = build(:user, email: 'invalid-email')
        expect(user).not_to be_valid
        expect(user.errors[:email]).to include('is invalid')
      end

      it 'is invalid with an empty email' do
        user = build(:user, email: '')
        expect(user).not_to be_valid
        expect(user.errors[:email]).to include("can't be blank")
      end
    end

    describe 'password validation' do
      it 'is invalid with password shorter than 6 characters' do
        user = build(:user, password: '123', password_confirmation: '123')
        expect(user).not_to be_valid
        expect(user.errors[:password]).to include('is too short (minimum is 6 characters)')
      end

      it 'is invalid without password confirmation' do
        user = build(:user, password_confirmation: '')
        expect(user).not_to be_valid
        expect(user.errors[:password_confirmation]).to include("can't be blank")
      end

      it 'is invalid with mismatched password confirmation' do
        user = build(:user, password_confirmation: 'different_password')
        expect(user).not_to be_valid
        expect(user.errors[:password_confirmation]).to include("doesn't match Password")
      end
    end

    describe 'email uniqueness' do
      it 'is invalid with duplicate email' do
        create(:user, email: 'test@example.com')
        user = build(:user, email: 'test@example.com')
        expect(user).not_to be_valid
        expect(user.errors[:email]).to include('has already been taken')
      end

      it 'is invalid with duplicate email in different case' do
        create(:user, email: 'test@example.com')
        user = build(:user, email: 'TEST@EXAMPLE.COM')
        expect(user).not_to be_valid
        expect(user.errors[:email]).to include('has already been taken')
      end
    end
  end

  describe 'callbacks' do
    it 'downcases email before save' do
      user = create(:user, email: 'UPPERCASE@EXAMPLE.COM')
      expect(user.email).to eq('uppercase@example.com')
    end

    it 'downcases email on update' do
      user = create(:user, email: 'lowercase@example.com')
      user.update(email: 'NEWCASE@EXAMPLE.COM')
      expect(user.reload.email).to eq('newcase@example.com')
    end
  end

  describe 'authentication' do
    let(:user) { create(:user, password: 'secret123', password_confirmation: 'secret123') }

    it 'authenticates with correct password' do
      expect(user.authenticate('secret123')).to eq(user)
    end

    it 'does not authenticate with incorrect password' do
      expect(user.authenticate('wrong_password')).to be_falsey
    end

    it 'has secure password functionality' do
      expect(user).to respond_to(:password_digest)
      expect(user.password_digest).to be_present
    end

    it 'uses bcrypt for password verification' do
      bcrypt_password = BCrypt::Password.new(user.password_digest)
      expect(bcrypt_password).to eq('secret123')
    end
  end

  describe 'database constraints' do
    it 'enforces unique email at database level' do
      create(:user, email: 'unique@example.com')
      
      expect {
        User.create!(email: 'unique@example.com', password: 'password123', password_confirmation: 'password123')
      }.to raise_error(ActiveRecord::RecordInvalid)
    end
  end
end 