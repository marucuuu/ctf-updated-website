from django.urls import path
from . import views
from django.contrib.auth import views as auth_views


urlpatterns = [
    path('', views.setup, name='setup'),

    path('login/', views.login_view, name='login'),

    path('verify/', views.verify_view, name='verify'),


    path('forgot/', views.forgot_password_view, name='forgot_password'),
    path('reset/<uidb64>/<token>/', views.reset_password_view, name='reset_password'),
    
    path('profile/', views.profile, name='profile'),
    path('update_profile/', views.update_profile, name='update_profile'),



    path('change_password_temporary/', views.change_password_temporary, name='change_password_temporary'),


    path('faqs/', views.faqs, name='faqs'),


    path('student_dashboard/', views.student_dashboard, name='student_dashboard'),
    path('submission-data/', views.get_submission_data, name='submission_data'),  # New URL

    path('mark-all-notifications-as-read/', views.mark_all_notifications_as_read, name='mark_all_notifications_as_read'),
    path('notifications-count/', views.notifications_count, name='notifications_count'),    
    

    path('lessons/', views.lessons, name='lessons'),
    path('lesson/<int:id>/', views.lesson_detail, name='lesson_detail'),
    path('lesson/<int:lesson_id>/mark_done_reading/', views.mark_done_reading, name='mark_done_reading'),
    path('category_activity/', views.categories_activity, name='categories_activity'),


    path('chatbot/', views.chatbot_response, name='chatbot_response'),
    path('get-chat-history/', views.get_chat_history, name='get_chat_history'),


    path('challenges_student/', views.challenges_student, name='challenges_student'),
    path('challenge/<int:pk>/', views.challenge_detail, name='challenge_detail'),
    path('submit_flag/<int:challenge_id>/', views.submit_flag, name='submit_flag'),

    path('scoreboard_student/', views.scoreboard_student, name='scoreboard_student'),

    path('join_team/', views.join_team, name='join_team'),
    

    # PROFESSOR SIDE
    path('dashboard/', views.prof_dashboard, name='dashboard'),
    path('prof_user/', views.prof_user, name='prof_user'),
    path('download_csv_template/', views.download_csv_template, name='download_csv_template'),
    
    path('lesson/', views.prof_lesson, name='lesson'),
    path('add_activity/', views.add_activity, name='add_activity'),
    path('view_activity/', views.view_activity, name='view_activity'),
    path('edit_activity/', views.edit_activity, name='edit_activity'),
    path('delete_activity/', views.delete_activity, name='delete_activity'),

    
    path('view_challenges/', views.view_challenges, name='view_challenges'),
    path('teams/', views.add_teams, name='teams'),

    path('view_lessons/', views.view_lessons, name='view_lessons'),
    path('lessons/edit/', views.edit_lesson, name='edit_lesson'),
    path('lessons/delete/', views.delete_lesson, name='delete_lesson'),

    path('challenges/', views.prof_challenges, name='challenges'),
    path('edit_challenge/<int:challenge_id>/', views.edit_challenge, name='edit_challenge'),
    path('delete_challenge/<int:pk>/', views.delete_challenge, name='delete_challenge'),
    path('api/challenges/<int:pk>/', views.get_challenge_data, name='get_challenge_data'),
    path('api/sections/', views.get_user_profile_sections, name='get_user_profile_sections'),

    path('view_user/', views.view_user, name='view_user'),
    path('history/', views.history_logs, name='history_logs'),

    path('edit-user-section/', views.edit_user_section, name='edit_user_section'),
    path('edit_user_teams/', views.edit_user_teams, name='edit_user_teams'),
    path('remove_user_from_team/', views.remove_user_from_team, name='remove_user_from_team'),
    path('change_verification_status/', views.change_verification_status, name='change_verification_status'),
    path('teams/delete/<int:team_id>/', views.delete_team, name='delete_team'),

    path('notification/', views.notification, name='notification'),
    
    path('config/', views.configuration, name='configuration'),
    path('profile-settings/', views.profile_settings, name='profile_settings'),
    path('media/<path:path>', views.media_file_view, name='media_file'),
    
    # LOGOUT
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),

]

