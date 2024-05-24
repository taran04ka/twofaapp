class UsersController < ApplicationController
  before_action :authenticate_user!, except: %i[show_otp verify_otp]

  def show_otp
  end

  def verify_otp
    verifier = Rails.application.message_verifier(:otp_session)
    user_id = verifier.verify(session[:otp_token])
    user = User.find(user_id)

    if user.validate_and_consume_otp!(params[:otp_attempt])
      sign_in(:user, user)
      redirect_to root_path, notice: 'Logged in successfully!'
    else
      flash[:alert] = 'Invalid OTP code.'
      redirect_to new_user_session_path
    end
  end

  def enable_otp_show_qr
    if current_user.otp_required_for_login
      redirect_to root_path, alert: '2FA is already enabled.'
    else
      current_user.otp_secret = User.generate_otp_secret
      issuer = 'Your App'
      label = "#{issuer}:#{current_user.email}"

      @provisioning_uri = current_user.otp_provisioning_uri(label, issuer:)
      current_user.save!
    end
  end

  def enable_otp_verify
    if current_user.validate_and_consume_otp!(params[:otp_attempt])
      current_user.otp_required_for_login = true
      current_user.save!
      redirect_to root_path, notice: '2FA enabled successfully.'
    else
      redirect_to enable_otp_show_qr_users_path, alert: 'Invalid OTP code.'
    end
  end

  def disable_otp_verify
    if current_user.validate_and_consume_otp!(params[:otp_attempt])
      current_user.otp_required_for_login = false
      current_user.save!
      redirect_to root_path, notice: '2FA disabled successfully.'
    else
      redirect_to root_path, alert: 'Invalid OTP code.'
    end
  end
end
