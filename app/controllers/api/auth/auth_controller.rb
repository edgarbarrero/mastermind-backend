require 'bcrypt'
require 'jwt'

class Api::Auth::AuthController < ApplicationController
  
  def register
    user = User.new(user_params)
    
    if user.save
      render json: { 
        message: 'User registered successfully',
        user: { id: user.id, email: user.email }
      }, status: :created
    else
      render json: { 
        errors: user.errors.full_messages 
      }, status: :unprocessable_entity
    end
  end
  
  def login
    user = User.find_by(email: params[:email]&.downcase)
    
    if user&.authenticate(params[:password])
      token = JwtService.generate_token(user)
      render json: { 
        message: 'Login successful',
        user: { id: user.id, email: user.email },
        token: token
      }, status: :ok
    else
      render json: { 
        error: 'Invalid email or password' 
      }, status: :unauthorized
    end
  end
  
  private
  
  def user_params
    params.permit(:email, :password, :password_confirmation, :name)
  end
end 