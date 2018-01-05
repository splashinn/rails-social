# Rails 5 Starter with Social Login
Generate model User
```
rails g model User name username email password_digest api_key is_admin:boolean role
```

Generate model Identity
```
rails g model identity user:references provider:string access_token:string refresh_token:string uid:string name:string email:string nick_name:string image:string phone:string urls:string raw:json oauth_expires_at:datetime

rails db:migrate
```

Generate controller Home and Sessions
```
rails g controller home show
rails g controller Sessions create destroy
```

Now we need to set up a few routes. Modify your routes file so that it looks like the code listed below.
```ruby
# config/routes.rb:
Rails.application.routes.draw do
  # ...

  get 'auth/:provider/callback', to: 'sessions#create'
  get 'auth/failure', to: redirect('/')
  get 'signout', to: 'sessions#destroy', as: 'signout'

  resources :sessions, only: [:create, :destroy]
  resource :home, only: [:show]

  root to: "home#show"

  # ...
end
```

Add `gem 'omniauth-google-oauth2'` to Gemfile:
```ruby
#...
gem 'omniauth-google-oauth2'
#...
```
Don't forget run:
```
bundle install
```

And edit `config/initializers/omniauth.rb`:
```ruby
# config/initializers/omniauth.rb:
OmniAuth.config.logger = Rails.logger

Rails.application.config.middleware.use OmniAuth::Builder do
  provider :google_oauth2, 'my Google client id', 'my Google client secret', {client_options: {ssl: {ca_file: Rails.root.join("cacert.pem").to_s}}}
end
```

The next thing we need to do is add some code to our User model. Open your users model and modify it so that it looks like the code listed below.
```ruby
app/models/user.rb:
class User < ActiveRecord::Base
  #...

  def self.from_omniauth(auth)
    where(email: auth.info.email).first_or_initialize.tap do |user|
      user.email = auth.info.email
      user.name = auth.info.name
      user.save!

      user.identities.where(provider: auth.provider, uid: auth.uid).first_or_initialize.tap do |identity|
          identity.provider = auth.provider
          identity.uid = auth.uid
          identity.name = auth.info.name
          identity.email = auth.info.email
          identity.access_token = auth.credentials.token
          identity.oauth_expires_at = Time.at(auth.credentials.expires_at)
          identity.raw = auth.to_json
          identity.save!
      end
    end
  end
end
```

Next, we will need to add some code to our application controller that will allow us to determine if the user is logged in or not. Open your application controller and modify it so that it looks like the code listed below.
```ruby
# app/controllers/application_controller.rb:
class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception
  helper_method :current_user

  def current_user
    @current_user ||= User.find(session[:user_id]) if session[:user_id]
  end
end
```

Now, lets add some code to our sessions controller. This code tells rails how to return the callback that omniauth does. Open your Sessions controller and modify it so that it looks like the code listed below.
```ruby
# app/controllers/sessions_controller.rb:
class SessionsController < ApplicationController
  def create
    user = User.from_omniauth(request.env["omniauth.auth"])
    session[:user_id] = user.id
    redirect_to root_path
  end

  def destroy
    session[:user_id] = nil
    redirect_to root_path
  end
end
```

NOTE:
On Rails 5.1, I needed to change this line:
```
user = User.from_omniauth(env["omniauth.auth"])
to:
user = User.from_omniauth(request.env["omniauth.auth"])
```

Next, lets modify our application layout and add a sign in/sign out link. Open your application layout and modify it so that it looks like the code listed below.
```ruby
# app/views/layouts/application.html.erb:
<!DOCTYPE html>
<html>
  <head>
    <title>Google Auth Example App</title>
    <%= stylesheet_link_tag    "application", media: "all", "data-turbolinks-track" => true %>
    <%= javascript_include_tag "application", "data-turbolinks-track" => true %>
    <%= csrf_meta_tags %>
  </head>
  <body>
    <div>
      <% if current_user %>
        Signed in as <strong><%= current_user.name %></strong>!
        <%= link_to "Sign out", signout_path, id: "sign_out" %>
      <% else %>
        <%= link_to "Sign in with Google", "/auth/google_oauth2", id: "sign_in" %>
      <% end %>
    </div>
    <div>
    <%= yield %>
    </div>
  </body>
```

