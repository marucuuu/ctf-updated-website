from collections import defaultdict
from datetime import datetime, timedelta
import json
import os
import random
import string
import uuid
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, update_session_auth_hash, get_user_model
from django.contrib.auth.decorators import user_passes_test, login_required
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm, PasswordChangeForm, SetPasswordForm
from django.contrib.auth.hashers import make_password
from django.urls import reverse
from django.views.decorators.http import require_POST
from django.http import FileResponse, HttpResponse, HttpResponseRedirect, JsonResponse
from django.contrib import messages 
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.utils.translation import gettext_lazy as _
from .forms import ActivityForm, ChallengeForm, InviteForm, LessonForm, ProfilePictureForm, TeamForm, NotificationForm, EmailForm, SetPasswordForm
from .models import Activity, ActivityLog, Challenge, ChallengeLeaderboard, DashboardConfig, FailedSubmission, Lesson, StudentActivityAnswer, Submission, User, Team, UserProfile, ChatInteraction, Notification, Invitation
from .token_generator import expiring_token_generator
from django.utils import timezone
import openai, logging, csv, re
from django.contrib.sites.shortcuts import get_current_site
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.core.mail import EmailMultiAlternatives
from django.utils.html import strip_tags
from openai.error import APIConnectionError
from requests.exceptions import RequestException
from django.core.cache import cache
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.db.models import Q  # Import Q for advanced filtering
from django.db.models import Min, Sum, Count

openai.api_key = settings.OPENAI_API_KEY



def password_required(function):
    """Decorator to ensure user has changed their temporary password."""
    def wrap(request, *args, **kwargs):
        # Check if the user needs to change their password
        if request.user.userprofile.must_change_password:
            return redirect('change_password_temporary')  # Redirect to the change password page
        return function(request, *args, **kwargs)
    return wrap


# error 404 
def pagenotfound(request, exception=None):
    return render(request, 'error/pagenotfound.html', {'error_message': exception})

def challengenotfound(request, exception=None):
    return render(request, 'error/challenge.html', {'error_message': exception})


# setup admin account if not exist

def setup(request):
    # Check if a superuser already exists
    if User.objects.filter(is_superuser=True).exists():
        return redirect('login')
    
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        email = request.POST.get('email')  # Capture the email field from the form submission
        
        if form.is_valid():
            user = form.save(commit=False)
            user.is_superuser = True
            user.is_staff = True
            user.email = email  # Save the email to the user object
            user.save()

            # Create the UserProfile with the role set to 'admin' and mark it as verified
            UserProfile.objects.create(user=user, role='admin', verified=True)

            return redirect('login')
    else:
        form = UserCreationForm()
    
    return render(request, 'setup/setup.html', {'form': form})



# chatbot ai
# Helper function to strip HTML tags
def strip_html_tags(text):
    """
    Remove HTML tags from the input text.
    """
    clean = re.compile('<.*?>')
    return re.sub(clean, '', text)

# Function to summarize a specific lesson's content
def summarize_lesson_content_with_analogy(lesson):
    """
    Summarizes the content of a Lesson object and provides an analogy using the OpenAI API.

    Args:
        lesson (Lesson): The Lesson object to summarize.

    Returns:
        str: A brief summary of the lesson's content with an analogy.
    """
    if not lesson.content:
        return "No content available to summarize."

    # Strip HTML tags from content
    lesson_name = strip_html_tags(lesson.name)
    lesson_category = strip_html_tags(lesson.category)
    lesson_content = strip_html_tags(lesson.content)

    # Create a prompt for summarizing the lesson and generating an analogy
    lesson_summary_prompt = (
        f"Summarize this cybersecurity lesson for a student:\n\n"
        f"Lesson name is '{lesson_name}' and its category is '{lesson_category}'.\n"
        f"Lesson Content: {lesson_content}\n\n"
        f"After summarizing, provide an analogy that helps explain the main concept to a beginner."
    )

    # Call the OpenAI API to summarize and generate an analogy
    try:
        lesson_response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful assistant knowledgeable in cybersecurity."},
                {"role": "user", "content": lesson_summary_prompt}
            ]
        )
        lesson_output = lesson_response['choices'][0]['message']['content'].strip()

        # Format the final output
        return (
            f"This is the summarized lesson with an analogy:\n\n"
            f"Lesson Name: {lesson_name}\n"
            f"{lesson_output}\n\n"
            f" For more details, please check the full lesson."
        )
    except Exception as e:
        return f"An error occurred while summarizing the lesson and generating an analogy: {e}"


# Function to list and summarize available lessons
def list_lessons():
    """
    Lists the names of all visible lessons in a numbered format with a short introduction using the OpenAI API.

    Returns:
        str: A short introduction followed by a numbered list of lesson names.
    """
    lessons = Lesson.objects.filter(visible=True).order_by('category', 'name')
    if not lessons.exists():
        return "No lessons are currently available."

    # Prepare lesson names
    lesson_names = [lesson.name for lesson in lessons]

    # Construct the AI prompt for listing lesson names
    prompt = (
        "You are an assistant who provides information about lessons. "
        "Below is a list of lesson names. Create a response with an introduction: "
        "'These are the available lessons in the lesson module' followed by a numbered list of the lesson names.\n\n"
    )
    prompt += "\n".join(lesson_names)

    # Call OpenAI to generate the lesson list
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful assistant knowledgeable in lesson summaries."},
                {"role": "user", "content": prompt}
            ]
        )
        lesson_list = response['choices'][0]['message']['content'].strip()
        return lesson_list
    except Exception as e:
        return f"An error occurred while listing lessons: {e}"


@csrf_exempt
def chatbot_response(request):
    """
    Handles chatbot interactions.
    """
    if request.method == 'POST':
        user_message = request.POST.get('message')

        if not user_message:
            return JsonResponse({'message': 'No message provided'}, status=400)

        final_response = ""

        # Check if the user requests to list available lessons
        if 'list lessons' in user_message.lower() or 'available lessons' in user_message.lower():
            lesson_list = list_lessons()
            final_response = lesson_list
        else:
            # Check if the user's message relates to any specific lesson
            lessons = Lesson.objects.filter(visible=True)
            lesson_reference = None
            for lesson in lessons:
                if lesson.name.lower() in user_message.lower() or lesson.category.lower() in user_message.lower():
                    lesson_reference = lesson
                    break

            if lesson_reference:
                # Summarize the lesson content
                lesson_summary = summarize_lesson_content_with_analogy(lesson_reference)
                final_response = (
                    f"{lesson_summary}"
                    f"For more details, please check the full lesson."
                )
            else:
                # If no lesson matches, provide a general cybersecurity-related response
                system_content = (
                    "You are a helpful assistant knowledgeable in cybersecurity. "
                    "Please provide responses related to cybersecurity topics, including data breaches, "
                    "cryptography, and forensics."
                )

                # Generate chatbot response using OpenAI API
                response = openai.ChatCompletion.create(
                    model="gpt-3.5-turbo",
                    messages=[{"role": "system", "content": system_content},
                              {"role": "user", "content": user_message}]
                )
                final_response = response['choices'][0]['message']['content'].strip()

        # Save interaction to the database
        interaction = ChatInteraction.objects.create(
            user=request.user,
            user_message=user_message,
            bot_response=final_response
        )

        # Return JSON response
        return JsonResponse({
            'message': final_response,
            'timestamp': interaction.timestamp.isoformat()
        })

    return JsonResponse({'message': 'Invalid request method'}, status=405)
@login_required
def get_chat_history(request):
    """
    Returns the user's chat history.
    """
    if request.method == 'GET':
        interactions = ChatInteraction.objects.filter(user=request.user).values('user_message', 'bot_response', 'timestamp')

        # Convert timestamps to ISO format
        chat_history = [
            {
                'user_message': interaction['user_message'],
                'bot_response': interaction['bot_response'],
                'timestamp': interaction['timestamp'].isoformat()
            }
            for interaction in interactions
        ]

        return JsonResponse({'chat_history': chat_history})

    return JsonResponse({'message': 'Invalid request method'}, status=405)
# chatbot end



# STUDENT SIDE # STUDENT SIDE # STUDENT SIDE # STUDENT SIDE # STUDENT SIDE # STUDENT SIDE # STUDENT SIDE # STUDENT SIDE # STUDENT SIDE # STUDENT SIDE # STUDENT SIDE # STUDENT SIDE



# DASHBOARD WITH AI START



def format_analysis_text(text):
    # Split the text into lines
    lines = text.splitlines()
    formatted_text = ""
    inside_list = False
    list_counter = 0  # To keep track of numbering across multiple sections

    # Loop through each line to detect numbered lists
    for line in lines:
        # Match lines starting with a number followed by a period and space
        if re.match(r'^\d+\.\s', line):  
            if not inside_list:
                formatted_text += "<ol>"  # Start a new ordered list
                inside_list = True
            list_counter += 1
            # Adjust the numbering based on the matched number
            formatted_text += f"<li>{line[line.find('.')+2:].strip()}</li>"  # Strip the number and period
        else:
            if inside_list:
                formatted_text += "</ol>"  # Close the ordered list
                inside_list = False
            formatted_text += f"<p>{line.strip()}</p>"  # For non-numbered lines

    # Ensure we close any remaining open list
    if inside_list:
        formatted_text += "</ol>"
    
    return formatted_text


def fetch_cybersecurity_trends():
    """
    Fetches the latest trends in cybersecurity using OpenAI's API, limited to 5 items.
    Only fetches trends if there is new failed submission data, ensuring efficiency.
    """
    prompt = "List the latest trends in cybersecurity in bullet points."

    try:
        # Generate the OpenAI response
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {
                    "role": "system",
                    "content": "You are an expert in cybersecurity."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            max_tokens=350,
            temperature=0.9
        )

        # Extract trends from the OpenAI response
        trends = response.choices[0].message['content'].strip()

        # Clean and format the trends into a list, limiting to 5 trends
        trends_list = [trend.lstrip('-').strip() for trend in trends.split('\n') if trend.strip()]
        limited_trends = trends_list[:5]  # Select the first 5 trends

        logger.debug(f"Fetched trends: {limited_trends}")  # Debug log for fetched trends
        return limited_trends

    except openai.error.OpenAIError as e:
        logger.error(f"OpenAI API error occurred while fetching trends: {str(e)}")
        return ["Error fetching trends from OpenAI API."]
    except Exception as e:
        logger.error(f"Unexpected error occurred while fetching trends: {str(e)}")
        return ["An unexpected error occurred while fetching trends."]




def analyze_data(profile):
    """
    Analyzes the student's performance based on challenges and practice activities.
    Suggests lessons, provides a summary, and offers key takeaways.
    Only processes analysis if there is new data since the last analysis.
    """
    now = timezone.now()

    try:
        # Check if there is new data since the last analysis
        last_analysis_update = profile.last_analysis_update or timezone.make_aware(datetime.min)

        new_submissions = Submission.objects.filter(
            user_profile=profile,
            submission_time__gt=last_analysis_update
        ).exists()

        new_activities = StudentActivityAnswer.objects.filter(
            student_profile=profile,
            date_answered__gt=last_analysis_update
        ).exists()

        if not new_submissions and not new_activities:
            return profile.last_analysis, profile.last_suggested_lesson

        # Analyze challenges
        submissions = Submission.objects.filter(user_profile=profile)
        correct_challenges = submissions.filter(is_correct=True).count()
        failed_challenges = submissions.filter(is_correct=False).count()

        # Analyze practice activities
        activities = StudentActivityAnswer.objects.filter(student_profile=profile)
        correct_activities = activities.filter(is_correct=True).count()
        failed_activities = activities.filter(is_correct=False).count()
        total_attempts = activities.aggregate(total_attempts=Sum('incorrect_attempts'))['total_attempts'] or 0

        # Analyze most failed challenge
        failed_challenge_data = submissions.filter(is_correct=False).values('challenge').annotate(
            fail_count=Count('challenge')
        ).order_by('-fail_count').first()

        most_failed_challenge = None
        most_failed_challenge_name = "No challenges attempted yet"
        if failed_challenge_data:
            most_failed_challenge = Challenge.objects.get(id=failed_challenge_data['challenge'])
            most_failed_challenge_name = most_failed_challenge.name

        # Analyze practice activity categories
        activity_category_data = activities.values('activity__category').annotate(
            correct_count=Sum('is_correct'),
            incorrect_count=Sum('incorrect_attempts')
        ).order_by('-correct_count')

        highest_correct_category = "N/A"
        highest_incorrect_category = "N/A"

        if activity_category_data:
            if activity_category_data[0]['correct_count'] > 0:
                highest_correct_category = activity_category_data[0]['activity__category']

            highest_incorrect_category_data = sorted(
                activity_category_data, key=lambda x: x['incorrect_count'], reverse=True
            )
            if highest_incorrect_category_data[0]['incorrect_count'] > 0:
                highest_incorrect_category = highest_incorrect_category_data[0]['activity__category']

        # Analyze most failed challenge for suggestions
        challenge = None
        if failed_challenge_data:
            challenge = Challenge.objects.get(id=failed_challenge_data['challenge'])
        elif profile.completed_challenges.exists():
            challenge = profile.completed_challenges.order_by('?').first()

        # Lesson suggestion
        visible_lessons = Lesson.objects.filter(visible=True)
        if not visible_lessons.exists():
            return "No relevant lessons available.", None

        related_lessons = visible_lessons.filter(category__icontains=challenge.category) if challenge else visible_lessons
        suggested_lesson = related_lessons.first() if related_lessons.count() == 1 else random.choice(related_lessons)

        # Summarize the suggested lesson
        suggested_lesson_name = suggested_lesson.name  # Already plain text due to LessonForm
        lesson_summary_prompt = (
            f"Summarize the following lesson in 3 to 5 sentences:\n"
            f"Lesson name: {suggested_lesson_name}\n"
            f"Category: {suggested_lesson.category}\n"
            f"Description: {suggested_lesson.description}\n"
            f"Content overview: {strip_html_tags(suggested_lesson.content)}"
        )

        openai_response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{
                "role": "system",
                "content": "You are an assistant that summarizes lesson content in 3 to 5 sentences."
            },
            {"role": "user", "content": lesson_summary_prompt}],
            max_tokens=150,
            temperature=0.9
        )
        lesson_summary = openai_response.choices[0].message['content'].strip()

        # Fetch cybersecurity trends
        trends = fetch_cybersecurity_trends()

        # Generate key takeaways with OpenAI based on the student's performance
        performance_data = {
            'correct_challenges': correct_challenges,
            'failed_challenges': failed_challenges,
            'correct_activities': correct_activities,
            'failed_activities': failed_activities,
            'total_attempts': total_attempts,
            'most_failed_challenge': most_failed_challenge_name,
            'highest_correct_category': highest_correct_category,
            'highest_incorrect_category': highest_incorrect_category
        }

        key_takeaways_prompt = (
            "Based on the following performance data, generate key takeaways for a student in 2 to 3 sentences. "
            "The key takeaways should be constructive and focus on strengths, weaknesses, and specific guidance for improvement. "
            "Please avoid using bullet points and keep the response as a natural paragraph of text.\n\n"
            f"Performance Data: {performance_data}\n\n"
            "Provide a concise, helpful analysis."
        )

        key_takeaways_openai_response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{
                "role": "system",
                "content": "You are an assistant that provides concise performance feedback based on student data."
            },
            {"role": "user", "content": key_takeaways_prompt}],
            max_tokens=100,
            temperature=0.7
        )

        key_takeaways = key_takeaways_openai_response.choices[0].message['content'].strip()

        # Compile analysis
        submission_analysis = (
            f"{profile.alias or 'The student'} has made {correct_challenges} correct challenge submissions and {failed_challenges} failed challenge submissions, "
            f"indicating areas where focused improvement is needed. The performance comparison highlights both strengths and areas for growth.\n\n"
            f"Most failed challenge: '{most_failed_challenge_name}'\n\n"
            f"{key_takeaways}\n\n"
            f"Suggested Lesson: {suggested_lesson_name}\n"
            f"Summary: {lesson_summary}"
        )

        # Save the analysis to the profile
        profile.last_analysis = submission_analysis
        profile.last_suggested_lesson = suggested_lesson
        profile.last_correct_submissions = correct_challenges
        profile.last_failed_submissions = failed_challenges
        profile.last_analysis_update = now
        profile.cybersecurity_trends = "\n".join(trends)
        profile.save()

        return profile.last_analysis, suggested_lesson

    except openai.error.OpenAIError as e:
        logger.error(f"OpenAI API error occurred during analysis: {str(e)}")
        return "Error processing the analysis due to OpenAI API error.", None
    except Exception as e:
        logger.error(f"Unexpected error occurred during analysis: {str(e)}")
        return "An unexpected error occurred while analyzing the student's data.", None





def mark_all_notifications_as_read(request):
    if request.method == "POST":
        notifications = Notification.objects.filter(user=request.user, is_read=False)
        notifications.update(is_read=True)
        
        # Ensure count of unread notifications is zero after marking all as read
        unread_count = Notification.objects.filter(user=request.user, is_read=False).count()
        
        return JsonResponse({'success': True, 'unread_count': unread_count})
    return JsonResponse({'success': False})

def notifications_count(request):
    unread_count = Notification.objects.filter(user=request.user, is_read=False).count()
    return JsonResponse({'unread_count': unread_count})

@login_required(login_url='login')
def student_dashboard(request):
    try:
        profile = UserProfile.objects.get(user=request.user)
        if not profile.verified:
            return redirect('login')
    except UserProfile.DoesNotExist:
        return redirect('login')

    # Fetch dashboard configuration, notifications, and other context data
    config = DashboardConfig.objects.first() or DashboardConfig.objects.create()
    notifications = Notification.objects.filter(user=request.user).order_by('-created_at')
    unread_notifications_count = Notification.objects.filter(user=request.user, is_read=False).count()
    success_rate = profile.calculate_success_rate()

    # Calculate team scores and rankings
    all_teams = Team.objects.all()
    team_scores = {}
    for team in all_teams:
        team_completed_challenges = Challenge.objects.filter(scoring_type='team', completed_teams=team)
        team_score = sum(challenge.points for challenge in team_completed_challenges)
        team_scores[team] = team_score

    ranked_teams = sorted(team_scores.items(), key=lambda x: x[1], reverse=True)

    # Fetch and annotate students with completed challenges
    students = UserProfile.objects.filter(points__gt=0).exclude(alias__isnull=True).exclude(alias='')\
        .annotate(completed_challenges_count=Count('completed_challenges')).order_by('-points')

    # Add rank to each student
    for index, student in enumerate(students, start=1):
        student.rank = index

    # Fetch Highest Correct Challenge
    highest_correct = (
        Submission.objects.filter(user_profile=profile, is_correct=True)
        .values('challenge__name')  # Use `name` instead of `title`
        .annotate(count=Count('id'))
        .order_by('-count')
        .first()
    )

    # Fetch Highest Incorrect Challenge
    highest_incorrect = (
        Submission.objects.filter(user_profile=profile, is_correct=False)
        .values('challenge__name')  # Use `name` instead of `title`
        .annotate(count=Count('id'))
        .order_by('-count')
        .first()
    )

    # Fetch Challenge to Improve
    challenge_to_improve = (
        Submission.objects.filter(user_profile=profile, is_correct=False)
        .select_related('challenge')
        .order_by('-submission_time')
        .first()
    )

    # Other required data for the dashboard
    challenge_count = Challenge.objects.filter(visible=True).count()
    lesson_count = Lesson.objects.filter(visible=True).count()

    analysis = "No submission data available."
    suggested_lesson = None
    suggested_lesson_plain = None  # Plain text version
    has_submission_data = profile.correct_submissions > 0 or profile.failed_submissions > 0

    last_analysis_update = profile.last_analysis_update

    try:
        if has_submission_data:
            analysis, suggested_lesson = analyze_data(profile)
            if suggested_lesson:
                suggested_lesson_plain = {
                    'id': suggested_lesson.id,
                    'name': strip_tags(suggested_lesson.name),
                    'description': strip_tags(suggested_lesson.description)
                }
    except (APIConnectionError, RequestException, Exception):
        pass

    # Fetch submission activity
    submissions = Submission.objects.filter(user_profile=profile).select_related('challenge').order_by('-submission_time')

    # Calculate total score
    total_score = sum(submission.challenge.points if submission.is_correct else 0 for submission in submissions)

    # Fetch student activity statistics
    student_activity_data = StudentActivityAnswer.objects.filter(student_profile=profile)

    total_activities_attempted = student_activity_data.count()
    correct_activities = student_activity_data.filter(is_correct=True).count()

    # Aggregate incorrect attempts directly using the `incorrect_attempts` field
    total_incorrect_attempts = student_activity_data.aggregate(total_incorrect=Sum('incorrect_attempts'))['total_incorrect'] or 0

    # Calculate activity performance ratio considering incorrect attempts
    if total_activities_attempted > 0:
        # Penalize incorrect attempts
        activity_performance_ratio = (
            (correct_activities / (correct_activities + total_incorrect_attempts)) * 100
        )
    else:
        activity_performance_ratio = 0

    # Compare activity performance with correct/incorrect challenge attempts
    challenge_performance_ratio = (
        profile.correct_submissions / (profile.correct_submissions + profile.failed_submissions) * 100
        if (profile.correct_submissions + profile.failed_submissions) > 0 else 0
    )

    # Fetch lessons and calculate completion by category
    lessons_by_category = {}
    all_categories = Lesson.objects.values_list('category', flat=True).distinct()
    
    for category in all_categories:
        lessons = Lesson.objects.filter(category=category)
        total_lessons = len(lessons)
        completed_lessons = sum(1 for lesson in lessons if lesson in profile.read_lessons.all())
        completion_percentage = (completed_lessons / total_lessons) * 100 if total_lessons > 0 else 0
        lessons_by_category[category] = {
            'lessons': lessons,
            'completion_percentage': completion_percentage
        }

    # Pass all the necessary context to the template
    return render(request, 'student_dashboard.html', {
        'config': config,
        'notifications': notifications,
        'unread_notifications_count': unread_notifications_count,
        'success_rate': success_rate,
        'total_attempts': profile.correct_submissions + profile.failed_submissions,
        'completed_challenges_count': profile.completed_challenges.count(),
        'correct_submissions': profile.correct_submissions,
        'failed_submissions': profile.failed_submissions,
        'students': students,
        'ranked_teams': ranked_teams,
        'challenge_count': challenge_count,
        'lesson_count': lesson_count,
        'analysis': analysis,
        'suggested_lesson': suggested_lesson_plain,  # Pass plain text version
        'trends': profile.cybersecurity_trends.split('\n') if profile.cybersecurity_trends else [],
        'last_analysis_update': last_analysis_update,
        'total_points': profile.points,  # Pass total points to the template
        'submissions': submissions,  # Add submission data
        'total_score': total_score,  # Add total score to the context
        'lessons_by_category': lessons_by_category,
        'submissions': submissions,
        'activity_correct_attempts': correct_activities,
        'activity_incorrect_attempts': total_incorrect_attempts,
        'activity_performance_ratio': activity_performance_ratio,
        'challenge_performance_ratio': challenge_performance_ratio,
        'highest_correct': highest_correct,
        'highest_incorrect': highest_incorrect,
        'challenge_to_improve': challenge_to_improve,
    })






# DASHBOARD WITH AI END






# PROFILE SETTINGS START

@login_required(login_url='login')

def profile(request):
    user = request.user

    # Profile update logic
    if request.method == 'POST' and 'update_profile' in request.POST:
        username = request.POST.get('username')
        first_name = request.POST.get('first_name', '')
        last_name = request.POST.get('last_name', '')
        section = request.POST.get('section', '')  # Retrieve the section

        # Enforce email immutability: retrieve from the current user object
        email = user.email  

        # Update user profile details
        user.username = username
        user.first_name = first_name
        user.last_name = last_name

        # Save alias and section if using a profile model
        user_profile = user.userprofile
        user_profile.alias = request.POST.get('alias', '')
        user_profile.section = section  # Update the section
        user_profile.save()

        user.save()
        messages.success(request, 'Your profile has been updated successfully.')
        return redirect('profile')

    # Password change logic
    password_form = PasswordChangeForm(user)
    if request.method == 'POST' and 'change_password' in request.POST:
        password_form = PasswordChangeForm(user, request.POST)
        if password_form.is_valid():
            user = password_form.save()
            # Update session hash to prevent logout after password change
            update_session_auth_hash(request, user)
            messages.success(request, 'Your password has been changed successfully.')
            return redirect('profile')
        else:
            # Handle specific errors, prioritize one message
            if 'old_password' in password_form.errors:
                messages.warning(request, 'The old password you entered is incorrect.')
            elif '__all__' in password_form.errors:  # Form-wide errors, such as password mismatch
                messages.warning(request, 'The new passwords do not match.')
            else:
                # Show the first field-specific error if others exist
                first_field = list(password_form.errors.keys())[0]
                first_error = password_form.errors[first_field][0]
                messages.warning(request, first_error)

    # Pass profile and password forms to the template
    profile_form = get_user_profile_form(user)
    return render(request, 'profile.html', {
        'profile_form': profile_form,
        'password_form': password_form
    })

@login_required(login_url='login')
def update_profile(request):
    if request.method == 'POST':
        user = request.user

        # Retrieve existing values
        current_username = user.username
        current_first_name = user.first_name
        current_last_name = user.last_name
        current_alias = user.userprofile.alias
        current_section = user.userprofile.section  # Retrieve the current section (but we don't allow changes)

        # Get submitted values from the form
        new_username = request.POST.get('username')
        new_first_name = request.POST.get('first_name', '')
        new_last_name = request.POST.get('last_name', '')
        new_alias = request.POST.get('alias', '')
        # Section is not updated as it's readonly
        new_section = current_section  # Do not allow section to be changed

        # Compare values to determine if changes were made
        if (
            new_username == current_username and
            new_first_name == current_first_name and
            new_last_name == current_last_name and
            new_alias == current_alias  # Section is never updated
        ):
            messages.info(request, 'No changes detected.')
            return redirect('profile')

        # Update fields only if they have changed
        user.username = new_username
        user.first_name = new_first_name
        user.last_name = new_last_name

        # Save alias (section remains unchanged)
        user_profile = user.userprofile
        user_profile.alias = new_alias
        # Section remains the same, don't update it
        user_profile.save()

        # Save user
        user.save()
        messages.success(request, 'Profile updated successfully.')
        return redirect('profile')

    return redirect('profile')


def get_user_profile_form(user):
    return {
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'alias': user.userprofile.alias,  # Fetch alias if using profile
        'section': user.userprofile.section  # Fetch section if it's part of the profile
    }

# PROFILE SETTINGS END


# forgot password start
User = get_user_model()

def forgot_password_view(request):
    if request.method == 'POST':
        form = EmailForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            user = User.objects.filter(email=email).first()
            if user:
                user_profile = getattr(user, 'userprofile', None)
                if user_profile and user_profile.must_change_password:
                    form.add_error('email', 'You must complete the initial password change before resetting your password.')
                    return render(request, 'forgotpassword/forgotpassword.html', {'form': form})

                try:
                    # Check if the email was sent recently and if the token has expired
                    last_email_time = request.session.get('email_sent_time')
                    if last_email_time:
                        last_email_time = timezone.datetime.fromisoformat(last_email_time)
                        if timezone.now() < last_email_time + timezone.timedelta(minutes=expiring_token_generator.token_lifetime):
                            form.add_error('email', 'An email has already been sent recently. Please check your inbox.')
                            return render(request, 'forgotpassword/forgotpassword.html', {'form': form})

                    # Generate token and send email
                    token = expiring_token_generator.make_token(user)
                    uid = urlsafe_base64_encode(force_bytes(user.pk))
                    domain = get_current_site(request).domain
                    reset_link = request.build_absolute_uri(f"/reset/{uid}/{token}/")

                    # Use the function to send the email
                    send_password_reset_email(user, reset_link)

                    # Update session with the email sent time
                    request.session['email_sent'] = True
                    request.session['email_sent_time'] = timezone.now().isoformat()

                    return render(request, 'forgotpassword/email_sent.html', {'email': email})
                except Exception as e:
                    return render(request, 'error/forgotpassworderror.html', {'error_message': str(e)})
            else:
                form.add_error('email', 'No account found with this email address.')
    else:
        form = EmailForm()

    return render(request, 'forgotpassword/forgotpassword.html', {'form': form})

def reset_password_view(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user and expiring_token_generator.check_token(user, token):
        if request.method == 'POST':
            form = SetPasswordForm(user, request.POST)
            if form.is_valid():
                try:
                    form.save()
                    update_session_auth_hash(request, user)
                    request.session.pop('email_sent', None)

                    return render(request, 'forgotpassword/reset_success.html')
                except Exception as e:
                    return render(request, 'error/forgotpassworderror.html', {'error_message': str(e)})
        else:
            form = SetPasswordForm(user)

        return render(request, 'forgotpassword/reset_password.html', {'form': form})
    else:
        return render(request, 'error/forgotpassworderror.html', {'error_message': 'Invalid or expired link'})
    
def send_password_reset_email(user, reset_link):
    subject = 'Password Reset Request'
    from_email = settings.DEFAULT_FROM_EMAIL  # Make sure this is configured correctly
    to_email = [user.email]

    # Load HTML content from the template with context
    html_content = render_to_string('forgotpassword/reset_email.html', {
        'user': user,
        'link': reset_link
    })
    # Create plain text by stripping HTML tags
    text_content = strip_tags(html_content)

    # Create email
    email = EmailMultiAlternatives(subject, text_content, from_email, to_email)
    # Attach the HTML version
    email.attach_alternative(html_content, "text/html")

    # Send email
    email.send()
    
# forgot password end







# VERIFY ACCOUNT START

def verify_view(request):
    if not request.user.is_authenticated:
        messages.error(request, 'You need to log in to verify your account.')
        return redirect('login')

    if request.method == 'POST':
        if 'verification_code' in request.POST:
            code = request.POST.get('verification_code')

            try:
                user_profile = UserProfile.objects.get(user=request.user)
            except UserProfile.DoesNotExist:
                messages.error(request, 'User profile does not exist.')
                return redirect('login')

            # Check if the code matches and if it's within the valid time period
            current_time = timezone.now()
            if (user_profile.verification_code == code and
                user_profile.verification_code_sent_at and
                current_time <= user_profile.verification_code_sent_at + timezone.timedelta(minutes=1)):
                user_profile.verified = True
                user_profile.verification_code = None  # Clear the code after successful verification
                user_profile.save()
                return redirect('dashboard' if request.user.is_superuser else 'student_dashboard')
            else:
                messages.warning(request, 'Invalid or expired verification code.')

        elif 'resend_code' in request.POST:
            try:
                user_profile = UserProfile.objects.get(user=request.user)
            except UserProfile.DoesNotExist:
                messages.error(request, 'User profile does not exist.')
                return redirect('login')

            # Check if the previous verification code has expired
            if user_profile.verification_code and timezone.now() <= user_profile.verification_code_sent_at + timezone.timedelta(minutes=1):
                messages.warning(request, 'You can only request a new code after the previous one has expired.')
            else:
                # Generate a new 6-digit verification code
                new_code = str(uuid.uuid4().int)[:6]  # Generate a new 6-digit code
                user_profile.verification_code = new_code
                user_profile.verification_code_sent_at = timezone.now()
                user_profile.save()

                # Load HTML content from the template with context
                html_content = render_to_string('verify/verify_resend_email.html', {
                    'user': request.user,
                    'verification_code': new_code,
                })
                
                # Create plain text by stripping HTML tags
                text_content = strip_tags(html_content)

                # Create email
                email = EmailMultiAlternatives(
                    'Your New Verification Code',
                    text_content,
                    settings.DEFAULT_FROM_EMAIL,
                    [request.user.email]
                )
                
                # Attach the HTML version
                email.attach_alternative(html_content, "text/html")

                # Send email
                email.send()

                messages.info(request, 'A new verification code has been sent to your email.')

    # Pass the verification code sent at timestamp to the template context
    try:
        user_profile = UserProfile.objects.get(user=request.user)
        verification_code_sent_at = user_profile.verification_code_sent_at
    except UserProfile.DoesNotExist:
        verification_code_sent_at = None

    return render(request, 'verify/verify.html', {
        'verification_code_sent_at': verification_code_sent_at,
    })


# VERIFY ACCOUNT END






# LOGIN VIEW START

def csrf_failure(request, reason=""):
    # Add a toast message for CSRF failure
    messages.warning(request, 'Try to login again')

    # Redirect the user to the login page when CSRF verification fails
    return redirect('login')

def login_view(request):
    # Check if the system has been set up (superuser exists)
    if not User.objects.filter(is_superuser=True).exists():
        return redirect('setup')

    config = DashboardConfig.objects.first() or DashboardConfig.objects.create()

    form = AuthenticationForm(request, data=request.POST or None)

    if request.method == 'POST':
        username_or_email = request.POST.get('username')
        password = request.POST.get('password')

        user = User.objects.filter(username=username_or_email).first()
        if not user:
            user = User.objects.filter(email=username_or_email).first()

        if user and authenticate(username=user.username, password=password):
            login(request, user)

            # Retrieve the user profile
            try:
                user_profile = UserProfile.objects.get(user=user)
            except UserProfile.DoesNotExist:
                user_profile = None

            if user_profile:
                if user_profile.must_change_password:
                    return redirect('change_password_temporary')

                if not user_profile.verified:
                    if user_profile.verification_code and user_profile.verification_code_sent_at:
                        code_expired = timezone.now() - user_profile.verification_code_sent_at > timezone.timedelta(minutes=15)

                        if code_expired:
                            messages.warning(request, 'The verification code has expired. Please request a new one.')
                            return redirect('verify') 
                        else:
                            return redirect('verify')  

                    else:
                        user_profile.generate_verification_code()
                        user_profile.verification_code_sent_at = timezone.now()
                        user_profile.save()

                        html_content = render_to_string('verify/verify_sent_email.html', {
                            'user': user,
                            'verification_code': user_profile.verification_code,
                        })
                        
                        text_content = strip_tags(html_content)

                        email = EmailMultiAlternatives(
                            'Your Verification Code',
                            text_content,
                            'no-reply@example.com',
                            [user.email]
                        )
                        email.attach_alternative(html_content, "text/html")
                        email.send()

                        messages.info(request, 'A verification code has been sent to your email.')
                        return redirect('verify')

            if user.is_superuser:
                return redirect('dashboard')
            else:
                return redirect('student_dashboard')

        form.add_error(None, 'Invalid username/email or password.')
        messages.info(request, 'Invalid username/email or password.')
        return redirect('login')
    
    return render(request, 'login.html', {
        'form': form,
        'notification_template': 'notification/notification.html',
        'config': config  # Pass the config to the template
    })


# LOGIN VIEW END


# REGISTER VIEW START

def register_student(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        section = request.POST.get('section', '').upper()  # Convert to uppercase

        errors = []

        # Check if username or email already exists
        if User.objects.filter(username=username).exists():
            errors.append('Username already exists.')
        if User.objects.filter(email=email).exists():
            errors.append('Email address already exists.')

        if errors:
            for error in errors:
                messages.error(request, error)
        else:
            temp_password = generate_temporary_password()  # Generate a temporary password

            # Create student user
            user = User.objects.create(
                username=username,
                email=email,
                password=make_password(temp_password)
            )
            UserProfile.objects.create(
                user=user,
                role='student',
                verified=False,  # Students need verification
                must_change_password=True,
                section=section
            )

            send_welcome_email(user, temp_password)  # Send login details via email

            messages.success(request, 'Registration successful! Check your email for login details.')
            return redirect('login')

    return render(request, 'register.html')


# REGISTER VIEW END






# VIEW LESSON BY STUDENTS START

@login_required(login_url='login')
def lessons(request):
    # Filter lessons to only include those that are visible
    lessons = Lesson.objects.filter(visible=True)

    # Group lessons by category
    lessons_by_category = {}
    for lesson in lessons:
        category = lesson.category
        if category not in lessons_by_category:
            lessons_by_category[category] = []
        lessons_by_category[category].append(lesson)

    # Fetch notifications specific to the user and related to team invitations
    notifications = Notification.objects.filter(user=request.user).order_by('-created_at')

    unread_notifications_count = Notification.objects.filter(user=request.user, is_read=False).count()
    
    return render(request, 'lesson.html', {
        'lessons_by_category': lessons_by_category,
        'notifications': notifications,
        'unread_notifications_count': unread_notifications_count,
    })
    

@login_required(login_url='login')
def lesson_detail(request, id):
    lesson = get_object_or_404(Lesson, id=id)
    notifications = Notification.objects.filter(user=request.user).order_by('-created_at')
    unread_notifications_count = Notification.objects.filter(user=request.user, is_read=False).count()

    # Check if the user has marked all lessons in this category as "done"
    all_lessons_in_category = Lesson.objects.filter(category=lesson.category).order_by('publish_date')  # Ensure lessons are ordered
    read_lessons_in_category = request.user.userprofile.read_lessons.filter(category=lesson.category)

    all_done_in_category = False
    if all_lessons_in_category.count() > 0:
        all_done_in_category = all_lessons_in_category.count() == read_lessons_in_category.count()

    # Get the next lesson within the category (based on publish_date or any other logic)
    current_index = list(all_lessons_in_category).index(lesson)
    next_lesson = None
    if current_index + 1 < len(all_lessons_in_category):
        next_lesson = all_lessons_in_category[current_index + 1]

    return render(request, 'lesson_detail.html', {
        'lesson': lesson,
        'user': request.user,
        'notifications': notifications,
        'unread_notifications_count': unread_notifications_count,
        'all_done_in_category': all_done_in_category,
        'next_lesson': next_lesson,  # Pass the next lesson to the template
    })



def mark_done_reading(request, lesson_id):
    lesson = get_object_or_404(Lesson, id=lesson_id)
    user_profile = request.user.userprofile

    # Add lesson to read_lessons if not already added
    if lesson not in user_profile.read_lessons.all():
        user_profile.read_lessons.add(lesson)
        messages.success(request, 'Lesson marked as done reading!')

    return redirect('lesson_detail', id=lesson_id)


# VIEW LESSON BY STUDENTS END







# VIEW LESSON ACTIVITIES BY STUDENTS START


@login_required(login_url='login')
def categories_activity(request):
    # Fetch all activities and categories
    activities = Activity.objects.all().order_by('category')
    categories = Activity.objects.values_list('category', flat=True).distinct()

    # Mapping for category names between Activity and Lesson models
    category_mapping = {
        'general': 'General',
        'osint': 'Open Source Intelligence',
        'cryptography': 'Cryptography',
        'forensics': 'Forensics',
    }

    # Standardize category names (e.g., for 'general' -> 'GENERAL')
    standardized_categories = [category.upper() for category in categories]

    # Group activities by category
    activities_by_category = {}
    for activity in activities:
        standardized_category = activity.category.upper()
        if standardized_category not in activities_by_category:
            activities_by_category[standardized_category] = []
        activities_by_category[standardized_category].append(activity)

    # Convert activities_by_category dict into a list of tuples (category, activities)
    activities_by_category_list = [(category, activities_by_category[category]) for category in standardized_categories]

    # Get notifications for the user
    notifications = Notification.objects.filter(user=request.user).order_by('-created_at')
    unread_notifications_count = Notification.objects.filter(user=request.user, is_read=False).count()

    # List to hold feedback and attempt tracking
    answered_activity_ids = []  # List of activity IDs that the student has answered
    feedback = []  # Feedback for each activity
    incorrect_attempts = {}  # Incorrect attempt count per activity

    # Check if student has marked all lessons as read in the relevant categories
    categories_with_unread_lessons = []  # Categories with unread lessons
    student_profile = request.user.userprofile

    # Iterate through all the categories
    for category in standardized_categories:
        lesson_category = category_mapping.get(category, category)  # Map activity category to lesson category
        category_lessons = Lesson.objects.filter(category__iexact=lesson_category, visible=True)

        # Check if the student has read all lessons in this category
        unread_lessons = category_lessons.exclude(id__in=student_profile.read_lessons.all())

        if unread_lessons.exists():
            # If there are unread lessons, we'll prevent the student from seeing activities for this category
            categories_with_unread_lessons.append(category)

    # Filter activities that the student can see (only show activities if all lessons in the category are marked as read)
    visible_activities_by_category = {}
    for category, activities in activities_by_category.items():
        if category not in categories_with_unread_lessons:
            visible_activities_by_category[category] = activities

    # Proceed with processing activities if the user is a student and if they have interacted with activities
    if request.user.userprofile.role == 'student':
        # Check if the student has already answered the activities
        for activity in activities:
            if StudentActivityAnswer.objects.filter(
                student_profile=request.user.userprofile,
                activity=activity
            ).exists():
                answered_activity_ids.append(activity.id)

                # Get the student's answer record
                student_answer_record = StudentActivityAnswer.objects.get(
                    student_profile=request.user.userprofile,
                    activity=activity
                )
                # Provide feedback based on whether the answer is correct
                feedback.append({
                    'activity_id': activity.id,
                    'message': "Your answer is correct!" if student_answer_record.is_correct else "Incorrect answer. Please try again."
                })

                # Track the number of incorrect attempts
                incorrect_attempts[activity.id] = student_answer_record.incorrect_attempts

        if request.method == 'POST':
            activity_id = request.POST.get('activity_id')
            student_answer = request.POST.get('answer')
            activity = Activity.objects.get(id=activity_id)
            student_profile = request.user.userprofile

            student_answer_record, created = StudentActivityAnswer.objects.get_or_create(
                student_profile=student_profile,
                activity=activity
            )

            student_answer_record.student_answer = student_answer
            student_answer_record.mark_correct()  # Mark the answer as correct or incorrect
            student_answer_record.save()

            # Add a notification message only if the student's answer is correct
            if student_answer_record.is_correct:
                # Send a success message and a notification
                messages.success(request, "Correct Answer, Good work!")
                
            else:
                # Just notify the student that their answer is incorrect without specifying the activity
                messages.info(request, "Incorrect answer. Please try again.")

            # Rebuild the feedback list after saving the new answer
            feedback.append({
                'activity_id': activity.id,
                'message': "Your answer is correct!" if student_answer_record.is_correct else "Incorrect answer. Please try again."
            })

            # Track the number of incorrect attempts
            incorrect_attempts[activity.id] = student_answer_record.incorrect_attempts

            return redirect('categories_activity')

    return render(request, 'category_activity.html', {
        'user': request.user,
        'notifications': notifications,
        'unread_notifications_count': unread_notifications_count,
        'activities_by_category_list': [(category, visible_activities_by_category.get(category, [])) for category in standardized_categories],
        'categories': standardized_categories,  # Pass the standardized categories list
        'answered_activity_ids': answered_activity_ids,
        'feedback': feedback,  # Pass the feedback list
        'incorrect_attempts': incorrect_attempts,  # Pass the incorrect attempt count
        'categories_with_unread_lessons': categories_with_unread_lessons,  # Pass the categories with unread lessons
    })






# VIEW LESSON ACTIVITIES BY STUDENTS END















# VIEW CHALLENGES BY STUDENTS START

@login_required(login_url='login')
def challenges_student(request):
    user_profile = UserProfile.objects.get(user=request.user)

    # Filter challenges based on visibility and section
    challenges = Challenge.objects.filter(
        visible=True
    ).filter(
        section__in=[user_profile.section, None, '']  # Show challenges with matching section or no section
    )

    completed_challenges = user_profile.completed_challenges.all()

    # Get the user's team, if any
    user_team = user_profile.user.teams.first()

    categories = {
        'individual': {},
        'team': {},
    }

    for challenge in challenges:
        # Exclude challenges of type 'team' if the user is not part of a team
        if challenge.scoring_type == 'team' and not user_team:
            continue

        # Separate individual and team challenges
        if challenge.scoring_type == 'team':
            if challenge.category not in categories['team']:
                categories['team'][challenge.category] = {
                    'challenge_list': [],
                    'lesson_count': Lesson.objects.filter(category=challenge.category, visible=True).count(),  # Count lessons in this category
                }
            categories['team'][challenge.category]['challenge_list'].append({
                'challenge': challenge,
                'team_completed': user_team in challenge.completed_teams.all(),
            })
        else:
            if challenge.category not in categories['individual']:
                categories['individual'][challenge.category] = {
                    'challenge_list': [],
                    'lesson_count': Lesson.objects.filter(category=challenge.category, visible=True).count(),  # Count lessons in this category
                }

            category_activities = Activity.objects.filter(category=challenge.category)
            activities_completed = all(
                StudentActivityAnswer.objects.filter(student_profile=request.user.userprofile, activity=activity, is_correct=True).exists()
                for activity in category_activities
            )

            # Only show the individual challenge if all related activities are completed
            if activities_completed:
                categories['individual'][challenge.category]['challenge_list'].append({
                    'challenge': challenge,
                    'team_completed': False,  # Not applicable for individual challenges
                    'individual_completed': challenge in completed_challenges,
                })

    # Fetch notifications specific to the user
    notifications = Notification.objects.filter(user=request.user).order_by('-created_at')
    unread_notifications_count = Notification.objects.filter(user=request.user, is_read=False).count()

    return render(request, 'student_challenges.html', {
        'categories': categories,
        'completed_challenges': completed_challenges,
        'user_team': user_team,
        'notifications': notifications,
        'unread_notifications_count': unread_notifications_count,
    })

@login_required(login_url='login')
def challenge_detail(request, pk):
    # Fetch the challenge, or raise 404 if it doesn't exist
    challenge = get_object_or_404(Challenge, pk=pk)

    # Get the current user profile
    user_profile = UserProfile.objects.get(user=request.user)

    # Get the user's team (assuming the user can only be part of one team)
    user_team = user_profile.user.teams.first()

    # Check if the challenge is of type 'team'
    if challenge.scoring_type == 'team':
        # If the user is not part of any team, deny access
        if not user_team:
            return challengenotfound(request, exception="This is a team challenge, and you are not part of any team.")

        # Check if the user's team has completed the challenge
        if user_team in challenge.completed_teams.all():
            # If the user has left the team, deny access
            if user_profile.user not in user_team.users.all():
                return challengenotfound(request, exception="You are no longer part of the team that completed this challenge.")

    # Check if the challenge has a section and if it matches the user's section
    if challenge.section and challenge.section != user_profile.section:
        # Deny access if the user's section does not match the challenge's section
        return challengenotfound(request, exception="You are not allowed to access this challenge.")

    # If the challenge is not visible, redirect to another page
    if not challenge.visible:
        messages.error(request, "This challenge is not visible or accessible to you.")
        return redirect('challenges_student')  # Redirect to the student's challenges list

    # Fetch notifications specific to the user and related to team invitations
    notifications = Notification.objects.filter(user=request.user).order_by('-created_at')
    unread_notifications_count = Notification.objects.filter(user=request.user, is_read=False).count()

    # Process hints (split by newlines into a list)
    hints = challenge.hints.split('\n') if challenge.hints else []

    return render(request, 'challenge_detail.html', {
        'challenge': challenge,
        'hints': hints,
        'notifications': notifications,
        'unread_notifications_count': unread_notifications_count,
    })

@login_required(login_url='login')

def submit_flag(request, challenge_id):
    # Retrieve the challenge object or return a 404 if not found
    challenge = get_object_or_404(Challenge, pk=challenge_id)

    # Ensure category is provided
    if not challenge.category:
        messages.error(request, 'This challenge does not have a category assigned.')
        return redirect('challenge_detail', pk=challenge_id)

    user_profile = UserProfile.objects.get(user=request.user)
    user_team = user_profile.user.teams.first()  # Assuming the user is only in one team

    # Check if the challenge is visible
    if not challenge.visible:
        return render(request, 'student_challenges.html')

    # Check if the challenge deadline has passed
    if challenge.deadline and timezone.now() > challenge.deadline:
        messages.info(request, 'The deadline for this challenge has passed. You can no longer submit the flag.')
        return redirect('challenge_detail', pk=challenge_id)

    # Check if the challenge has already been completed by the user or team
    if challenge.scoring_type == 'individual' and challenge in user_profile.completed_challenges.all():
        messages.info(request, 'You have already completed this challenge.')
        return redirect('challenge_detail', pk=challenge_id)

    # If the challenge is team-based, we need to check if the team has completed the challenge
    if challenge.scoring_type == 'team' and user_team:
        if user_team in challenge.completed_teams.all():
            # If the team has completed the challenge, no user (including the user who left) should submit it
            messages.info(request, 'Your team has already completed this challenge. You can no longer submit it.')
            return redirect('challenge_detail', pk=challenge_id)

        # Check if the user has left the team
        if user_team not in user_profile.user.teams.all():
            # If the user has left the team, they should not be allowed to submit the challenge
            messages.info(request, 'You have left the team and can no longer submit this challenge.')
            return redirect('challenge_detail', pk=challenge_id)

    # Process the submission if none of the above conditions block it
    if request.method == 'POST':
        submitted_flag = request.POST.get('flag')

        # Check if the flag is empty
        if not submitted_flag:
            messages.error(request, 'Please enter a flag before submitting.')
            return redirect('challenge_detail', pk=challenge_id)

        # Create a new Submission instance
        submission = Submission(user_profile=user_profile, challenge=challenge)

        # Check if the submitted flag is correct
        if submitted_flag == challenge.flag:
            # Award points to the user
            user_profile.points += challenge.points

            # Update correct submissions and add challenge to completed challenges
            user_profile.correct_submissions += 1
            user_profile.last_correct_submissions += 1  # Update last correct submissions
            user_profile.completed_challenges.add(challenge)
            user_profile.save()

            # Update the leaderboard
            leaderboard_entry = ChallengeLeaderboard(challenge=challenge, user_profile=user_profile)
            leaderboard_entry.update_leaderboard()  # Update the leaderboard with correct submissions

            if challenge.scoring_type == 'team' and user_team:
                user_team.points += challenge.points
                user_team.save()
                challenge.completed_teams.add(user_team)

            challenge.save()

            messages.success(request, f'Correct flag! You have earned {challenge.points} points. Your team\'s score has also been updated.')

            # Mark submission as correct
            submission.is_correct = True

            # Log the submission in ActivityLog
            ActivityLog.objects.create(
                user=request.user,
                action='submission',
                description=f"Correct flag for challenge '{challenge.name}'",
            )
        else:
            # Increment failed submissions count
            user_profile.failed_submissions += 1
            user_profile.last_failed_submissions += 1  # Update last failed submissions
            messages.info(request, 'Incorrect flag. Please try again.')

            # Create a failed submission record
            FailedSubmission.objects.create(user_profile=user_profile, challenge=challenge)

            # Mark submission as incorrect
            submission.is_correct = False

            # Log the submission in ActivityLog
            ActivityLog.objects.create(
                user=request.user,
                action='submission',
                description=f"Incorrect flag for challenge '{challenge.name}'",
            )

        # Save the submission instance
        submission.save()

        # Save the profile to ensure all changes are persisted
        user_profile.save()

        return redirect('challenge_detail', pk=challenge_id)

    # If it's a GET request, render the challenge detail page
    return render(request, 'challenge_detail.html', {'challenge': challenge})


def get_submission_data(request):
    # Get today's date and calculate the range for the last 6 days
    end_date = timezone.now()
    start_date = end_date - timedelta(days=6)

    # Check if the user is a superuser/admin
    if request.user.is_superuser:
        # Fetch all submissions in the last 6 days
        submissions = Submission.objects.filter(submission_time__range=(start_date, end_date))
    else:
        # Fetch submissions for the logged-in user only
        user_profile = UserProfile.objects.get(user=request.user)
        submissions = Submission.objects.filter(user_profile=user_profile, submission_time__range=(start_date, end_date))

    # Aggregate submission data by date
    submission_count = {}
    for submission in submissions:
        date = submission.submission_time.date()
        if date not in submission_count:
            submission_count[date] = 0
        submission_count[date] += 1

    # Prepare data for the chart
    dates = [start_date.date() + timedelta(days=i) for i in range(7)]
    counts = [submission_count.get(date, 0) for date in dates]

    return JsonResponse({
        'dates': [date.strftime('%Y-%m-%d') for date in dates],
        'counts': counts
    })


    
# VIEW CHALLENGES BY STUDENTS END






# VIEW SCOREBOARD BY STUDENTS START

@login_required(login_url='login')
def scoreboard_student(request):
    # Get all teams
    all_teams = Team.objects.all()

    # Create a dictionary to store team scores
    team_scores = {}
    for team in all_teams:
        team_scores[team] = team.total_points()

    # Filter and order students by points
    students = UserProfile.objects.filter(points__gt=0).order_by('-points')

    # Assign rank based on position in the ordered list
    for index, student in enumerate(students, start=1):
        student.rank = index

    return render(request, 'scoreboard.html', {
        'students': students,
        'team_scores': team_scores
    })

# VIEW SCOREBOARD BY STUDENTS END








# JOIN TEAM BY STUDENTS START

@login_required(login_url='login')

def join_team(request):
    user_profile = get_object_or_404(UserProfile, user=request.user)
    teams = Team.objects.all()  # Fetch all teams for selection form
    team_form = TeamForm()  # Form for creating a new team
    invite_form = InviteForm()  # Form for inviting users

    if request.method == 'POST':
        if 'join_team' in request.POST:
            if user_profile.user.teams.exists():
                messages.warning(request, 'You can only join one team. Please leave your current team first.')
            else:
                team_id = request.POST.get('team_id')
                team_password = request.POST.get('team_password')
                team = get_object_or_404(Team, id=team_id)

                # Check if the user and the team creator belong to the same section
                if user_profile.section != team.created_by.userprofile.section:
                    messages.warning(request, 'You cannot join this team because you are not in the same section as the team creator.')
                elif team.users.count() >= 4:
                    messages.warning(request, 'This team already has 4 members. Please choose another team.')
                elif team.check_password(team_password):
                    user_profile.user.teams.add(team)
                    user_profile.save()
                    messages.success(request, f'You have successfully joined {team.name}.')
                else:
                    messages.warning(request, 'Incorrect password. Please try again.')
            return redirect('join_team')  # Redirect to avoid form resubmission

        elif 'leave_team' in request.POST:
            team_id = request.POST.get('team_id')
            team = get_object_or_404(Team, id=team_id)
            user_profile.user.teams.remove(team)
            user_profile.save()
            messages.warning(request, f'You have left {team.name}.')
            return redirect('join_team')  # Redirect to avoid form resubmission

        elif 'create_team' in request.POST:
            team_form = TeamForm(request.POST)
            if team_form.is_valid():
                team = team_form.save(commit=False)
                team.created_by = request.user
                team.save()
                team.users.add(request.user)
                messages.success(request, f'Team {team.name} has been created.')
                return redirect('join_team')  # Redirect to avoid form resubmission

        elif 'invite_user' in request.POST:
            invite_form = InviteForm(request.POST)
            if invite_form.is_valid():
                invited_username = invite_form.cleaned_data['invited_user']

                if invited_username == request.user.username:
                    messages.warning(request, 'You cannot invite yourself to the team.')
                else:
                    try:
                        invited_user = User.objects.get(username=invited_username)
                        team = user_profile.user.teams.first()

                        if team and team.created_by == request.user:
                            # Check if the inviter and invitee are in the same section
                            if user_profile.section != invited_user.userprofile.section:
                                messages.warning(
                                    request,
                                    f'{invited_username} is not in the same section as you. You can only invite users from your section.'
                                )
                            # Check if the invited user is already in another team
                            elif invited_user.teams.exists():
                                messages.warning(request, f'{invited_username} is already part of another team and cannot be invited.')
                            elif team.users.count() >= 4:
                                messages.warning(request, 'This team already has 4 members. You cannot invite more users.')
                            else:
                                # Check if the invited user is already in the team
                                if invited_user in team.users.all():
                                    messages.warning(request, f'{invited_username} is already a member of {team.name}.')
                                else:
                                    existing_invitation = Invitation.objects.filter(
                                        team=team, invited_user=invited_user, accepted=False
                                    ).first()

                                    if existing_invitation:
                                        messages.warning(request, f'You have already invited {invited_username}.')
                                    else:
                                        # Create an invitation
                                        invitation = Invitation.objects.create(
                                            team=team,
                                            invited_user=invited_user,
                                            invited_by=request.user
                                        )

                                        # Create a notification for the invited user
                                        notification_message = f'You have been invited to join {team.name}.'
                                        notification = Notification.objects.create(
                                            user=invited_user,
                                            sender=request.user,
                                            message=notification_message
                                        )

                                        # Send real-time notification via WebSocket
                                        channel_layer = get_channel_layer()
                                        async_to_sync(channel_layer.group_send)( 
                                            f"user_{invited_user.id}",
                                            {
                                                'type': 'send_notification',
                                                'message': notification.message,
                                                'created_at': str(notification.created_at),
                                                'sender': request.user.username  # Include the sender's username
                                            }
                                        )

                                        messages.success(request, f'{invited_username} has been invited to join {team.name}.')
                        else:
                            messages.warning(request, 'You do not have permission to invite users to this team.')
                    except User.DoesNotExist:
                        messages.warning(request, 'The user does not exist.')
            return redirect('join_team')  # Redirect to avoid form resubmission

        elif 'accept_invitation' in request.POST:
            invitation_id = request.POST.get('invitation_id')
            invitation = get_object_or_404(Invitation, id=invitation_id)

            if invitation.invited_user == request.user and not invitation.accepted:
                invitation.accepted = True
                invitation.save()
                team = invitation.team
                user_profile.user.teams.add(team)
                user_profile.save()
                messages.success(request, f'You have accepted the invitation to join {team.name}.')
            else:
                messages.warning(request, 'Invalid invitation or already accepted.')
            return redirect('join_team')  # Redirect to avoid form resubmission

    user_teams = user_profile.user.teams.all()
    team_members = []
    for team in user_teams:
        members = team.users.all()
        team_members.append({
            'team': team,
            'members': members
        })

    is_part_of_any_team = user_teams.exists()

    invitations = Invitation.objects.filter(invited_user=request.user, accepted=False).exclude(team__users=request.user)

    notifications = Notification.objects.filter(user=request.user).order_by('-created_at')

    unread_notifications_count = Notification.objects.filter(user=request.user, is_read=False).count()

    return render(request, 'team_join.html', {
        'team_members': team_members,
        'teams': teams,  # Pass the list of available teams for selection
        'is_part_of_any_team': is_part_of_any_team,  # Pass the flag
        'team_form': team_form,  # Pass the team creation form
        'invite_form': invite_form,  # Pass the invite form to the template
        'invitations': invitations,  # Pass the list of invitations to the template
        'notifications': notifications,
        'unread_notifications_count': unread_notifications_count,
    })



    
# JOIN TEAM BY STUDENTS END





# PROFESSOR SIDE # PROFESSOR SIDE # PROFESSOR SIDE # PROFESSOR SIDE # PROFESSOR SIDE # PROFESSOR SIDE # PROFESSOR SIDE # PROFESSOR SIDE # PROFESSOR SIDE # PROFESSOR SIDE


def superuser_required(view_func):
    decorated_view_func = user_passes_test(
        lambda user: user.is_superuser,
        login_url='/'
    )(view_func)
    return decorated_view_func

# PROFESSOR DASHBOARD START



def get_greeting():
    current_hour = timezone.localtime().hour
    if 5 <= current_hour < 12:
        return "Good Morning"
    elif 12 <= current_hour < 17:
        return "Good Afternoon"
    else:
        return "Good Evening"


@superuser_required
def prof_dashboard(request):
    # Fetch student data and calculate their ranks based on points
    students = UserProfile.objects.filter(user__is_superuser=False, user__is_staff=False).order_by('-points')
    for idx, student in enumerate(students, start=1):
        student.rank = idx
        # Calculate success rate dynamically
        correct_submissions = student.correct_submissions
        failed_submissions = student.failed_submissions
        total_submissions = correct_submissions + failed_submissions
        student.success_rate = (correct_submissions / total_submissions * 100) if total_submissions > 0 else 0

    # Average Success Rate across all students
    total_correct = UserProfile.objects.aggregate(Sum('correct_submissions'))['correct_submissions__sum'] or 0
    total_failed = UserProfile.objects.aggregate(Sum('failed_submissions'))['failed_submissions__sum'] or 0
    total_attempts = total_correct + total_failed
    average_success_rate = round((total_correct / total_attempts * 100), 2) if total_attempts > 0 else 0

    # Count totals for students, challenges, and teams
    student_count = User.objects.filter(is_superuser=False, is_staff=False).count()
    challenge_count = Challenge.objects.count()
    team_count = Team.objects.count()

    # Aggregate submissions for the last 7 days
    end_date = timezone.now()
    start_date = end_date - timedelta(days=6)
    submission_counts = defaultdict(int)
    submissions = Submission.objects.filter(submission_time__range=(start_date, end_date))
    for submission in submissions:
        submission_counts[submission.submission_time.date()] += 1

    # Prepare data for the submission chart
    submission_dates = [start_date.date() + timedelta(days=i) for i in range(7)]
    submission_data = [submission_counts.get(date, 0) for date in submission_dates]

    # Aggregate correct submissions by category
    correct_submissions = ChallengeLeaderboard.objects.values('challenge__category').annotate(total_correct=Sum('correct_submissions'))

    if correct_submissions:
        # Find the least number of correct submissions
        min_correct = correct_submissions.aggregate(min_correct=Min('total_correct'))['min_correct']

        # Get all categories with the least number of correct submissions
        least_solved_categories = correct_submissions.filter(total_correct=min_correct).values_list('challenge__category', flat=True)
    else:
        least_solved_categories = []

    # Join categories into a single string for display
    least_solved_category = ", ".join(least_solved_categories) if least_solved_categories else "N/A"

    # Get all unique categories
    all_categories = set(
        ChallengeLeaderboard.objects.values_list('challenge__category', flat=True)
    ).union(
        FailedSubmission.objects.values_list('challenge__category', flat=True)
    )

    # Aggregate correct submissions by category for the chart
    correct_submission_dict = {entry['challenge__category']: entry['total_correct'] for entry in correct_submissions}

    # Aggregate failed submissions by category
    failed_submissions = FailedSubmission.objects.values('challenge__category').annotate(total_failed=Count('id'))
    failed_submission_dict = {entry['challenge__category']: entry['total_failed'] for entry in failed_submissions}

    # Top Challenges
    top_correct_challenges = ChallengeLeaderboard.objects.values('challenge__name').annotate(total_correct=Sum('correct_submissions')).order_by('-total_correct')[:5]
    top_failed_challenges = FailedSubmission.objects.values('challenge__name').annotate(total_failed=Count('id')).order_by('-total_failed')[:5]

    # Prepare data for the correct and failed submissions chart
    categories = sorted(all_categories)  # Sorted list of categories for consistent ordering
    correct_submission_data = [correct_submission_dict.get(category, 0) for category in categories]
    failed_submission_data = [failed_submission_dict.get(category, 0) for category in categories]

    greeting_message = get_greeting()  # Determine the greeting based on the time of day

    return render(request, 'professors/prof_dashboard.html', {
        'students': students,
        'student_count': student_count,
        'challenge_count': challenge_count,
        'team_count': team_count,
        'submission_data': submission_data,
        'submission_dates': [date.strftime('%Y-%m-%d') for date in submission_dates],
        'categories': categories,
        'correct_submission_data': correct_submission_data,
        'failed_submission_data': failed_submission_data,
        'average_success_rate': average_success_rate,  # Rounded average success rate
        'top_correct_challenges': top_correct_challenges,
        'top_failed_challenges': top_failed_challenges,
        'least_solved_category': least_solved_category,  # Pass the least solved category to the template
        'greeting_message': greeting_message,  # Pass the greeting to the template
    })


# PROFESSOR DASHBOARD END




# PROFESSOR SEND NOTIFICATION START

logger = logging.getLogger(__name__)

@superuser_required
def notification(request):
    if request.method == 'POST':
        form = NotificationForm(request.POST)
        if form.is_valid():
            message = form.cleaned_data['message']
            recipients = form.cleaned_data['recipients']
            created_notifications = 0

            for recipient in recipients:
                if not Notification.objects.filter(user=recipient, message=message).exists():
                    notification = Notification.objects.create(
                        user=recipient,
                        sender=request.user,  # Add the sender here
                        message=message
                    )
                    created_notifications += 1

                    # Send the notification via WebSocket
                    channel_layer = get_channel_layer()
                    async_to_sync(channel_layer.group_send)(
                        f"user_{recipient.id}",
                        {
                            'type': 'send_notification',
                            'message': notification.message,
                            'created_at': str(notification.created_at),
                            'sender': request.user.username  # Include the sender's username
                        }
                    )

            if created_notifications > 0:
                messages.success(request, f'Notification sent successfully to {created_notifications} recipients!')
                if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                    return JsonResponse({'success': True, 'message': f'Notification sent successfully to {created_notifications} recipients!'})
            else:
                messages.warning(request, 'No new notifications were created as identical messages already exist.')
                if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                    return JsonResponse({'success': False, 'message': 'No new notifications were created as identical messages already exist.'})

            if not request.headers.get('x-requested-with') == 'XMLHttpRequest':
                return HttpResponseRedirect(reverse('notification'))
        else:
            messages.info(request, 'There was an error with the form submission.')
            if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                return JsonResponse({'success': False, 'message': 'There was an error with the form submission.'})
    else:
        form = NotificationForm()

    greeting_message = get_greeting()  # Determine the greeting based on the time of day
    return render(request, 'professors/prof_notification.html', {
        'form': form,
        'greeting_message': greeting_message,  # Pass the greeting to the template
    })



# PROFESSOR SEND NOTIFICATION END






# PROFESSOR ADD USER START


def download_csv_template(request):
    # Create a response object and set the content type to CSV
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="upload_user_template.csv"'

    # Create a CSV writer object
    writer = csv.writer(response)

    # Write the header row to the CSV file
    writer.writerow(['Username', 'Email', 'Section', 'Role', 'Verified'])

    return response

@login_required
def prof_user(request):
    # Check if the user is an 'admin'
    if request.user.userprofile.role != 'admin':
        return redirect('dashboard')

    # Check if the user needs to change their temporary password
    if request.user.userprofile.must_change_password:
        return redirect('change_password_temporary')

    if request.method == 'POST':
        if 'csv_file' in request.FILES:
            # Handle CSV upload
            csv_file = request.FILES.get('csv_file')
            if csv_file:
                decoded_file = csv_file.read().decode('utf-8').splitlines()
                reader = csv.DictReader(decoded_file)
                errors = []

                for row in reader:
                    username = row.get('Username')
                    email = row.get('Email')
                    role = row.get('Role')
                    verified = row.get('Verified', 'no').lower() == 'yes'
                    section = row.get('Section', '').upper()  # Convert section to uppercase

                    # Check for existing username and email
                    if User.objects.filter(username=username).exists():
                        errors.append(f'Username {username} already exists.')
                        continue
                    if User.objects.filter(email=email).exists():
                        errors.append(f'Email {email} already exists.')
                        continue

                    temp_password = generate_temporary_password()

                    if role == 'student':
                        user = User.objects.create(
                            username=username,
                            email=email,
                            password=make_password(temp_password)
                        )
                        UserProfile.objects.create(
                            user=user,
                            role='student',
                            verified=verified,
                            must_change_password=True,
                            section=section  # Save section as uppercase
                        )
                        send_welcome_email(user, temp_password)

                    elif role == 'professor':
                        user = User.objects.create(
                            username=username,
                            email=email,
                            password=make_password(temp_password),
                            is_superuser=True,
                            is_staff=True
                        )
                        UserProfile.objects.create(
                            user=user,
                            role='professor',
                            verified=True,
                            must_change_password=True,
                            section=section  # Save section as uppercase
                        )
                        send_welcome_email(user, temp_password)

                if errors:
                    for error in errors:
                        messages.info(request, error)
                else:
                    messages.success(request, 'Users added successfully from CSV.')

                return redirect('prof_user')

        else:
            # Handle single user creation
            username = request.POST.get('username')
            email = request.POST.get('email')
            role = request.POST.get('role')
            verified = request.POST.get('verified') == 'on'
            section = request.POST.get('section').upper()  # Convert entered section to uppercase

            errors = []

            if User.objects.filter(username=username).exists():
                errors.append('Username already exists.')
            if User.objects.filter(email=email).exists():
                errors.append('Email address already exists.')

            if errors:
                for error in errors:
                    messages.info(request, error)
            else:
                temp_password = generate_temporary_password()

                if role == 'student':
                    user = User.objects.create(
                        username=username,
                        email=email,
                        password=make_password(temp_password)
                    )
                    UserProfile.objects.create(
                        user=user,
                        role='student',
                        verified=verified,
                        must_change_password=True,
                        section=section  # Save section as uppercase
                    )
                    send_welcome_email(user, temp_password)

                elif role == 'professor':
                    user = User.objects.create(
                        username=username,
                        email=email,
                        password=make_password(temp_password),
                        is_superuser=True,
                        is_staff=True
                    )
                    UserProfile.objects.create(
                        user=user,
                        role='professor',
                        verified=True,
                        must_change_password=True,
                        section=section  # Save section as uppercase
                    )
                    send_welcome_email(user, temp_password)

                messages.success(request, 'User added successfully.')

            return redirect('prof_user')

    greeting_message = get_greeting()

    return render(request, 'professors/prof_user.html', {
        'greeting_message': greeting_message,
    })

# Function to send a welcome email with username and temporary password
def send_welcome_email(user, temp_password):
    """Sends a welcome email with username and temporary password."""
    html_content = render_to_string('temporary/welcome_email.html', {
        'user': user,
        'temporary_password': temp_password,
    })
    text_content = strip_tags(html_content)

    email_message = EmailMultiAlternatives(
        'Welcome to Our Platform',
        text_content,
        'no-reply@example.com',  # Make sure this email address is set in your settings
        [user.email]
    )
    email_message.attach_alternative(html_content, "text/html")
    email_message.send()

# Function to generate a random temporary password
def generate_temporary_password(length=8):
    """Generates a random temporary password with uppercase and lowercase letters."""
    characters = string.ascii_letters  # This includes both lowercase and uppercase letters
    temp_password = ''.join(random.choice(characters) for _ in range(length))
    return temp_password


def change_password_temporary(request):
    user_profile = UserProfile.objects.get(user=request.user)

    # Check if the user needs to change their password
    if not user_profile.must_change_password:
        return redirect('dashboard')  # Redirect to another page if the user doesn't need to change password

    # If the form is submitted via POST
    if request.method == 'POST':
        old_password = request.POST.get('old_password')
        new_password1 = request.POST.get('new_password1')
        new_password2 = request.POST.get('new_password2')

        # Check if the old password is correct
        user = authenticate(username=request.user.username, password=old_password)
        if user is None:
            messages.warning(request, 'The old password is incorrect. Please try again.')
            return redirect('change_password_temporary')  # Redirect back to the change password page if the old password is incorrect

        # Check if the new passwords match
        if new_password1 != new_password2:
            messages.warning(request, 'The new passwords do not match. Please try again.')
            return redirect('change_password_temporary')  # Redirect back to the change password page if passwords don't match

        # Proceed with updating the password using the SetPasswordForm
        form = SetPasswordForm(user=request.user, data=request.POST)
        if form.is_valid():
            form.save()  # Save the new password

            # If the profile required a password change, reset the flag
            if user_profile.must_change_password:
                user_profile.must_change_password = False
                user_profile.save()

            messages.success(request, 'Your password has been updated successfully.')
            return redirect('login')  # Redirect to login after success
        else:
            messages.error(request, 'Please correct the errors below.')

    else:
        # Show the change password form initially
        form = SetPasswordForm(user=request.user)

    return render(request, 'temporary/changepassword.html', {'form': form})

# PROFESSOR ADD USER END







# PROFESSOR ADD CHALLENGE START

@superuser_required
def prof_challenges(request):
    if request.user.userprofile.role != 'professor':
        # Redirect 'professor' to their dashboard
        return redirect('dashboard')  # Adjust this to the correct URL name for the professor's dashboard
    
    available_sections = UserProfile.objects.values_list('section', flat=True).distinct()
    section_choices = [('', 'All Section')] + [(section, section) for section in available_sections if section]  # Include "No Section" option

    if request.method == 'POST':
        form = ChallengeForm(request.POST, request.FILES)
        form.fields['section'].choices = section_choices  # Update form's section choices dynamically
        
        if form.is_valid():
            challenge = form.save(commit=False)  # Save the form without committing to the database yet
            challenge.section = form.cleaned_data.get('section')  # Store the selected section or None
            challenge.save()  # Save the challenge instance with the selected section
            print("Challenge saved:", Challenge.objects.last())  # Debugging
            messages.success(request, 'Challenge successfully added!')
            return redirect(reverse('challenges'))
        else:
            print("Form errors:", form.errors)  # Debugging
    else:
        form = ChallengeForm()
        form.fields['section'].choices = section_choices  # Update form's section choices dynamically

    greeting_message = get_greeting()

    return render(request, 'professors/prof_challenges.html', {
        'form': form,
        'greeting_message': greeting_message,
    })

@superuser_required
def get_challenge_data(request, pk):
    challenge = get_object_or_404(Challenge, pk=pk)
    data = {
        'name': challenge.name,
        'category': challenge.category,
        'content': challenge.content,  # Changed from description to content
        'points': challenge.points,
        'visible': challenge.visible,
        'hints': challenge.hints,
        'flag': challenge.flag,
        'link': challenge.link,
        'deadline': challenge.deadline.strftime('%Y-%m-%dT%H:%M') if challenge.deadline else None,
        'scoring_type': challenge.scoring_type,
    }
    return JsonResponse(data)


# PROFESSOR ADD CHALLENGE END







# PROFESSOR ADD LESSON START

@superuser_required
def prof_lesson(request):
    if request.user.userprofile.role != 'professor':
        # Redirect 'professor' to their dashboard
        return redirect('dashboard')  # Adjust this to the correct URL name for the professor's dashboard
    
    if request.method == 'POST':
        form = LessonForm(request.POST, request.FILES)
        if form.is_valid():
            form.save()
            messages.success(request, 'Lesson successfully added!')
            return redirect('lesson')  # Make sure 'lesson' matches your URL name
    else:
        form = LessonForm()

    greeting_message = get_greeting()  # Determine the greeting based on the time of day

    return render(request, 'professors/prof_lesson.html', {
        'form': form,
        'greeting_message': greeting_message,  # Pass the greeting to the template
        
        })


# PROFESSOR ADD LESSON END






# PROFESSOR ADD ACTIVITY CATEGORY START

@superuser_required
def add_activity(request):
    if request.user.userprofile.role != 'professor':
        # Redirect non-professors to their dashboard
        return redirect('dashboard')

    if request.method == 'POST':
        form = ActivityForm(request.POST)
        if form.is_valid():
            # Set the professor as the current user
            activity = form.save(commit=False)
            activity.professor = request.user  # Assign the professor
            activity.save()  # Save the activity to the database
            messages.success(request, 'Activity added successfully!')
            return redirect('add_activity')  # Redirect to the same page
        else:
            # If the form is not valid, display an error message
            messages.error(request, 'There was an error with your form. Please check the fields.')
    else:
        form = ActivityForm()

    greeting_message = get_greeting()  # Get the greeting message based on the time of day

    return render(request, 'professors/prof_activity.html', {
        'greeting_message': greeting_message,
        'form': form,
    })




# PROFESSOR ADD ACTIVITY CATEGORY END






# PROFESSOR CRUD ACTIVITY CATEGORY START

from itertools import groupby
from operator import attrgetter

def view_activity(request):
    if request.user.userprofile.role != 'professor':
        return redirect('dashboard')

    # Fetch all activities created by the logged-in professor, ordered by category
    activities = Activity.objects.filter(professor=request.user).order_by('category')

    # Group activities by category
    grouped_activities = {
        category: list(items) for category, items in groupby(activities, key=attrgetter('category'))
    }

    greeting_message = get_greeting()

    return render(request, 'professors/view_activity.html', {
        'greeting_message': greeting_message,
        'grouped_activities': grouped_activities,  # Pass grouped activities to the template
    })

def edit_activity(request):
    if request.method == 'POST':
        activity_id = request.POST.get('activity_id')
        activity = get_object_or_404(Activity, pk=activity_id, professor=request.user)

        # Update fields including due_date
        activity.question = request.POST.get('question')
        activity.category = request.POST.get('category')
        activity.correct_answer = request.POST.get('correct_answer')
        activity.due_date = request.POST.get('due_date')  # Capture and update due date

        activity.save()

        messages.success(request, 'Activity updated successfully.')
        return redirect('view_activity')

    return redirect('view_activity')
    

def delete_activity(request):
    if request.method == 'POST':
        activity_id = request.POST.get('activity_id')
        activity = get_object_or_404(Activity, pk=activity_id, professor=request.user)

        activity.delete()

        messages.success(request, 'Activity deleted successfully.')
        return redirect('view_activity')
    return redirect('view_activity')

# PROFESSOR CRUD ACTIVITY CATEGORY END




# PROFESSOR VIEW CHALLENGES CRUD START

@superuser_required
def view_challenges(request):
    if request.user.userprofile.role != 'professor':
        # Redirect 'professor' to their dashboard
        return redirect('dashboard')  # Adjust this to the correct URL name for the professor's dashboard
    
    challenges = Challenge.objects.all()
    
    # Categorize challenges by category
    categorized_challenges = defaultdict(list)
    for challenge in challenges:
        # Categorize by 'category' field, or 'Uncategorized' if no category is set
        category = challenge.category if challenge.category else 'Uncategorized'
        # Add challenge to category list along with its section
        categorized_challenges[category].append({
            'challenge': challenge,
            'section': challenge.section if challenge.section else 'All Section'  # Add section info
        })
    
    # Debugging: Log the categorized challenges
    print("Categorized Challenges: ", dict(categorized_challenges))
    
    greeting_message = get_greeting()  # Determine the greeting based on the time of day
    
    return render(request, 'professors/prof_view_challenges.html', {
        'categorized_challenges': dict(categorized_challenges),  # Convert defaultdict to dict for rendering
        'greeting_message': greeting_message,  # Pass the greeting to the template
    })


@superuser_required
@require_POST
def edit_challenge(request, challenge_id):
    if request.user.userprofile.role != 'professor':
        return redirect('dashboard')

    challenge = get_object_or_404(Challenge, pk=challenge_id)

    # Retrieve data from the form and update the challenge
    name = request.POST.get('name')
    category = request.POST.get('category')
    content = request.POST.get('content')
    points = request.POST.get('points')
    visible = 'visible' in request.POST
    scoring_type = request.POST.get('scoring_type')
    section = request.POST.get('section')
    link = request.POST.get('link')
    deadline = request.POST.get('deadline')
    file = request.FILES.get('file')
    flag = request.POST.get('flag')

    # Update challenge with the received data
    challenge.name = name
    challenge.category = category
    challenge.content = content
    challenge.points = points
    challenge.visible = visible
    challenge.scoring_type = scoring_type
    challenge.section = section
    challenge.link = link
    challenge.deadline = deadline if deadline else None
    challenge.flag = flag

    if file:
        challenge.file = file

    challenge.save()

    messages.success(request, f'Challenge "{name}" successfully updated.')
    return redirect('view_challenges')

def get_user_profile_sections(request):
    # Fetch available distinct sections, excluding empty or null values
    sections = UserProfile.objects.values_list('section', flat=True).exclude(section__isnull=True).exclude(section='')
    return JsonResponse({'sections': list(sections)})

@require_POST
@superuser_required
def delete_challenge(request, pk):
    if request.user.userprofile.role != 'professor':
        # Redirect 'professor' to their dashboard
        return redirect('dashboard')  # Adjust this to the correct URL name for the professor's dashboard
    
    challenge = get_object_or_404(Challenge, pk=pk)
    challenge.delete()
    messages.success(request, 'Challenge successfully deleted!')
    return redirect('view_challenges')

def complete_challenge(request, challenge_id):
    challenge = get_object_or_404(Challenge, pk=challenge_id)
    user_profile = get_object_or_404(UserProfile, user=request.user)

    # Mark the challenge as completed by adding it to the user's profile
    user_profile.completed_challenges.add(challenge)
    user_profile.save()

    messages.success(request, f'Challenge "{challenge.name}" marked as completed.')
    return redirect('view_challenges')

# PROFESSOR VIEW CHALLENGES CRUD END







# PROFESSOR VIEW LESSON CRUD START

@superuser_required
def view_lessons(request):
    if request.user.userprofile.role != 'professor':
        # Redirect 'professor' to their dashboard
        return redirect('dashboard')  # Adjust this to the correct URL name for the professor's dashboard
    
    lessons = Lesson.objects.all()

    # Add a 'plain_name' attribute for each lesson
    for lesson in lessons:
        lesson.plain_name = strip_tags(lesson.name)
        lesson.name = lesson.name.encode('utf-8').decode('unicode_escape')

    greeting_message = get_greeting()

    return render(request, 'professors/prof_view_lessons.html', {
        'lessons': lessons,
        'greeting_message': greeting_message,
    })

@superuser_required
def edit_lesson(request):
    if request.user.userprofile.role != 'professor':
        # Redirect 'professor' to their dashboard
        return redirect('dashboard')  # Adjust this to the correct URL name for the professor's dashboard
    
    if request.method == 'POST':
        lesson_id = request.POST.get('lesson_id')
        lesson = get_object_or_404(Lesson, pk=lesson_id)

        form = LessonForm(request.POST, request.FILES, instance=lesson)
        if form.is_valid():
            form.save()
            messages.success(request, 'Lesson successfully updated!')
            return redirect('view_lessons')
        else:
            messages.error(request, f'Error updating lesson: {form.errors}')
            return redirect('view_lessons')  # Add proper redirect for error case

    return redirect('view_lessons')

@superuser_required
def delete_lesson(request):
    if request.user.userprofile.role != 'professor':
        # Redirect 'professor' to their dashboard
        return redirect('dashboard')  # Adjust this to the correct URL name for the professor's dashboard
    
    if request.method == 'POST':
        lesson_id = request.POST.get('lesson_id')  # Get the lesson ID from the POST request
        lesson = get_object_or_404(Lesson, pk=lesson_id)  # Fetch the lesson object
        lesson.delete()  # Delete the lesson
        messages.success(request, 'Lesson successfully deleted!')  # Success message
        return redirect(reverse('view_lessons'))  # Redirect back to the lesson view
    return redirect(reverse('view_lessons'))  # Handle non-POST requests


# PROFESSOR VIEW LESSON CRUD END








# PROFESSOR VIEW USER CRUD START


@login_required
def view_user(request):
    # Check if the user is an 'admin'
    if request.user.userprofile.role != 'admin':
        # Redirect 'professor' to their dashboard
        return redirect('dashboard')  # Adjust this to the correct URL name for the professor's dashboard
    
    # Retrieve all non-admin users along with their UserProfile roles
    users = User.objects.filter(userprofile__role__in=['professor', 'student']).select_related('userprofile').prefetch_related('teams')
    teams = Team.objects.all()

    # Get distinct sections for the dropdown, excluding empty or null values
    sections = UserProfile.objects.filter(
        ~Q(section="") & Q(section__isnull=False)
    ).values_list('section', flat=True).distinct()

    # Prepare data structure for JavaScript
    user_teams = {
        user.id: list(user.teams.values('id', 'name'))
        for user in users
    }

    greeting_message = get_greeting()  # Determine the greeting based on the time of day
    
    return render(request, 'professors/prof_view_user.html', {
        'users': users,
        'teams': teams,
        'user_teams': user_teams,
        'sections': sections,  # Pass the distinct sections to the template
        'greeting_message': greeting_message,  # Pass the greeting to the template
    })

@require_POST
@superuser_required
def edit_user_teams(request):
    user_id = request.POST.get('user_id')
    team_ids = request.POST.getlist('teams')
    user = get_object_or_404(User, id=user_id)
    teams = Team.objects.filter(id__in=team_ids)
    user.teams.set(teams)
    user.save()
    messages.success(request, "User's teams were successfully updated.")
    return redirect('view_user')
    
@require_POST
@superuser_required
def edit_user_section(request):
    if request.method == 'POST' and request.user.userprofile.role == 'admin':
        try:
            # Load the request body
            data = json.loads(request.body)
            user_id = data.get('user_id')
            new_section = data.get('section')

            if not user_id or not new_section:
                return JsonResponse({'error': 'User ID and Section are required.'}, status=400)

            # Get the user and user profile
            user = get_object_or_404(User, id=user_id)
            user_profile = user.userprofile

            # Update the section
            user_profile.section = new_section.upper()  # Ensure section is saved in uppercase
            user_profile.save()

            messages.success(request, f"User's section was successfully updated to {new_section.upper()}.")
            return JsonResponse({'success': True})

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON format.'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    else:
        return JsonResponse({'error': 'Permission denied or invalid request'}, status=403)

@require_POST
@superuser_required
def remove_user_from_team(request):
    user_id = request.POST.get('user_id')
    team_id = request.POST.get('team_id')
    
    user = get_object_or_404(User, id=user_id)
    team = get_object_or_404(Team, id=team_id)
    
    user.teams.remove(team)
    user.save()
    messages.success(request, "User was successfully removed from the team.")
    
    return redirect('view_user')

@require_POST
@superuser_required
def change_verification_status(request):

    if request.user.userprofile.role != 'admin':
        # Redirect 'professor' to their dashboard
        return redirect('dashboard')  # Adjust this to the correct URL name for the professor's dashboard
    
    user_id = request.POST.get('user_id')
    verification_status = request.POST.get('verification_status') == 'True'
    
    user = get_object_or_404(User, id=user_id)
    user.userprofile.verified = verification_status
    user.userprofile.save()
    messages.success(request, "User's verification status was successfully updated.")
    
    return redirect('view_user')

# PROFESSOR VIEW USER CRUD END













# PROFESSOR ADD TEAM ADD/DELETE START

@superuser_required
def add_teams(request):
    if request.method == 'POST' and 'delete_team_id' not in request.POST:
        form = TeamForm(request.POST, user=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, "Team was successfully added.")
            return redirect(reverse('teams'))
    else:
        form = TeamForm()
    
    students = User.objects.filter(is_superuser=False)
    teams = Team.objects.all()  # Fetch all teams

    greeting_message = get_greeting()  # Determine the greeting based on the time of day

    return render(request, 'professors/prof_teams.html', {
        'form': form,
        'students': students,
        'teams': teams,  # Pass the list of teams
        'greeting_message': greeting_message,  # Pass the greeting to the template
    })

@superuser_required
def delete_team(request, team_id):
    team = get_object_or_404(Team, id=team_id)
    if request.method == 'POST':
        team.delete()
        messages.success(request, "Team was successfully deleted.")
        return redirect(reverse('teams'))

    return redirect(reverse('teams'))


# PROFESSOR ADD TEAM ADD/DELETE END






# PROFESSOR CONFIGURATION START

# Set up logging
logger = logging.getLogger(__name__)

@superuser_required

def configuration(request):
    config, created = DashboardConfig.objects.get_or_create(id=1)

    if request.method == "POST":
        config.show_leaderboards = request.POST.get('show_leaderboards', False) == 'on'
        config.show_team_scores = request.POST.get('show_team_scores', False) == 'on'
        config.show_report_and_stats = request.POST.get('show_report_and_stats', False) == 'on'
        config.show_submission_overview_chart = request.POST.get('show_submission_overview_chart', False) == 'on'
       

        # Handle the logo upload
        if 'logo' in request.FILES:
            config.logo = request.FILES['logo']
            logger.debug("Logo uploaded: %s", config.logo.url)  # Debugging
            config.save()
            logger.debug("Config saved successfully with logo: %s", config.logo.url)

        # Handle logo removal
        if request.POST.get('remove_logo'):
            config.logo = None

        config.save()
        messages.success(request, 'Dashboard configuration updated successfully!')
        return redirect('configuration')
    
    greeting_message = get_greeting()  # Determine the greeting based on the time of day
    

    context = {
        'config': config,
        'show_leaderboards': config.show_leaderboards,
        'show_team_scores': config.show_team_scores,
        'show_report_and_stats': config.show_report_and_stats,
        'show_submission_overview_chart': config.show_submission_overview_chart,
        'greeting_message': greeting_message,  # Pass the greeting to the template

    }
    return render(request, 'professors/config.html', context)

def media_file_view(request, path):
    file_path = os.path.join(settings.MEDIA_ROOT, path)
    if os.path.exists(file_path):
        return FileResponse(open(file_path, 'rb'))
    else:
        return HttpResponse(status=404)

# PROFESSOR CONFIGURATION END  










# PROFESSOR VIEW HISTORY LOGS START



@receiver(user_logged_in)
def log_user_login(sender, request, user, **kwargs):
    ActivityLog.objects.create(user=user, action='login', description='User logged in')


# Log activity when a user logs out
@receiver(user_logged_out)
def log_user_logout(sender, request, user, **kwargs):
    ActivityLog.objects.create(user=user, action='logout', description='User logged out')

# Log when a user views a lesson module
def log_lesson_view(request, lesson):
    ActivityLog.objects.create(
        user=request.user,
        action='viewed lesson',
        description=f'User viewed the lesson: {lesson.name}'
    )

# View to render history logs (including login/logout and submissions)
def history_logs(request):
    if request.user.userprofile.role != 'admin':
        # Redirect 'professor' to their dashboard
        return redirect('dashboard')  # Adjust this to the correct URL name for the professor's dashboard
    
    greeting_message = get_greeting()  # Determine the greeting based on the time of day

    # Retrieve the first 100 activity logs (including login, logout, and submissions)
    activity_logs = ActivityLog.objects.all().order_by('-timestamp')[:100]  # Limit to the first 100 logs

    # Get all users
    users = User.objects.all()

    return render(request, 'professors/history_logs.html', {
        'greeting_message': greeting_message,
        'activity_logs': activity_logs,
        'users': users,
    })


# PROFESSOR VIEW HISTORY LOGS END

def profile_settings(request):
    # Ensure only 'professor' or 'admin' can access this
    if request.user.userprofile.role not in ['professor', 'admin']:
        return redirect('dashboard')  # Adjust this to the correct URL name for the professor's dashboard
    
    user_profile = UserProfile.objects.get(user=request.user)
    user = request.user  # The User object itself
    
    # Add the first_name and last_name fields to the form
    if request.method == 'POST':
        form = ProfilePictureForm(request.POST, request.FILES, instance=user_profile)
        if form.is_valid():
            form.save()
            messages.success(request, 'Profile picture updated successfully!')
            
            # Handle first_name and last_name updates for professor/admin
            user.first_name = request.POST.get('first_name', user.first_name)
            user.last_name = request.POST.get('last_name', user.last_name)
            user.save()
            
            messages.success(request, 'Profile updated successfully!')
            return redirect('profile_settings')
    else:
        form = ProfilePictureForm(instance=user_profile)

    # Get a greeting message (optional)
    greeting_message = get_greeting()  # Define this function to generate time-based greetings
    
    return render(request, 'professors/profile_settings.html', {
        'form': form,
        'user_profile': user_profile,
        'user': user,
        'greeting_message': greeting_message,
    })