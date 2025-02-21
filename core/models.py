from django.db import models
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone
import uuid
from django.utils.timezone import now



class Challenge(models.Model):
    SCORING_TYPE_CHOICES = [
        ('individual', 'Individual'),
        ('team', 'Team'),
    ]

    CATEGORY_CHOICES = [
        ('general', 'General'),
        ('osint', 'Open Source Intelligence'),
        ('cryptography', 'Cryptography'),
        ('forensics', 'Forensics'),
    ]

    name = models.CharField(max_length=255)
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES)
    content = models.TextField()
    file = models.FileField(upload_to='challenges/files/', null=True, blank=True)
    link = models.URLField(null=True, blank=True)
    hints = models.TextField(null=True, blank=True)
    points = models.IntegerField()
    visible = models.BooleanField(default=True)
    flag = models.CharField(max_length=255, default='')
    deadline = models.DateTimeField(null=True, blank=True)
    completed_teams = models.ManyToManyField('Team', blank=True)
    scoring_type = models.CharField(max_length=10, choices=SCORING_TYPE_CHOICES, default='individual')
    section = models.CharField(max_length=10, blank=True, null=True)  # This is the section field

    def __str__(self):
        return self.name

    
# Shared category choices
CATEGORY_CHOICES = [
    ('general', 'General'),
    ('osint', 'Open Source Intelligence'),
    ('cryptography', 'Cryptography'),
    ('forensics', 'Forensics'),
]

class Lesson(models.Model):
    category = models.CharField(max_length=100, choices=CATEGORY_CHOICES)  # Use shared choices
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    content = models.TextField()
    file = models.FileField(upload_to='lessons/', blank=True, null=True)
    publish_date = models.DateField()
    visible = models.BooleanField(default=True)

    def __str__(self):
        return self.name


class Activity(models.Model):
    ACTIVITY_TYPE_CHOICES = [
        ('mcq', 'Multiple Choice'),
        ('identification', 'Identification'),
    ]

    category = models.CharField(max_length=100, choices=CATEGORY_CHOICES)  # Use shared choices
    professor = models.ForeignKey(User, on_delete=models.CASCADE)
    activity_type = models.CharField(max_length=20, choices=ACTIVITY_TYPE_CHOICES)
    question = models.TextField()
    correct_answer = models.TextField()
    option_a = models.TextField(blank=True, null=True)  # Only for MCQ
    option_b = models.TextField(blank=True, null=True)  # Only for MCQ
    option_c = models.TextField(blank=True, null=True)  # Only for MCQ
    due_date = models.DateTimeField(default=now)

    def __str__(self):
        return f"Activity ({self.get_activity_type_display()}) in {self.get_category_display()} by {self.professor.username}"


class StudentActivityAnswer(models.Model):
    student_profile = models.ForeignKey('UserProfile', on_delete=models.CASCADE)
    activity = models.ForeignKey(Activity, on_delete=models.CASCADE)
    student_answer = models.TextField()
    is_correct = models.BooleanField(default=False)
    date_answered = models.DateTimeField(auto_now_add=True)
    incorrect_attempts = models.IntegerField(default=0)  # New field to track incorrect attempts

    def __str__(self):
        return f"{self.student_profile.user.username} - {self.activity.id}"
    
    def mark_correct(self):
        """ Marks the activity as completed and correct if the answer matches the correct answer """
        self.is_correct = self.student_answer.strip().lower() == self.activity.correct_answer.strip().lower()
        if not self.is_correct:
            self.incorrect_attempts += 1  # Increment incorrect attempts if the answer is incorrect
        self.save()
    
        
class Team(models.Model):
    name = models.CharField(max_length=100)
    password = models.CharField(max_length=128)  # Storing hashed passwords
    users = models.ManyToManyField(User, related_name='teams', blank=True)
    points = models.IntegerField(default=0)  # New field to track team points directly
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_teams')


    def __str__(self):
        return self.name

    def set_password(self, raw_password):
        self.password = make_password(raw_password)

    def total_points(self):
        """Calculate the total points by summing the points of all users in the team."""
        return sum(user.userprofile.points for user in self.users.all())

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)
    
class Invitation(models.Model):
    team = models.ForeignKey(Team, on_delete=models.CASCADE, related_name='invites')
    invited_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='team_invites')
    invited_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_invites')
    created_at = models.DateTimeField(auto_now_add=True)
    accepted = models.BooleanField(default=False)
    expires_at = models.DateTimeField(null=True, blank=True)  # Expiration time

    def is_expired(self):
        return timezone.now() > self.expires_at
    
    def __str__(self):
        return f"{self.invited_user.username} invited to {self.team.name} by {self.invited_by.username}"

class FailedSubmission(models.Model):
    user_profile = models.ForeignKey('UserProfile', on_delete=models.CASCADE)  # Use string reference here
    challenge = models.ForeignKey('Challenge', on_delete=models.CASCADE)
    submission_time = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user_profile.user.username} failed {self.challenge.title} on {self.submission_time}"

class Submission(models.Model):
    user_profile = models.ForeignKey('UserProfile', on_delete=models.CASCADE)
    challenge = models.ForeignKey('Challenge', on_delete=models.CASCADE)
    is_correct = models.BooleanField(default=False)
    submission_time = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Submission by {self.user_profile.user.username} for {self.challenge.title} on {self.submission_time}"

class ChallengeLeaderboard(models.Model):
    challenge = models.ForeignKey('Challenge', on_delete=models.CASCADE)
    user_profile = models.ForeignKey('UserProfile', on_delete=models.CASCADE)
    correct_submissions = models.IntegerField(default=0)

    class Meta:
        unique_together = ('challenge', 'user_profile')  # Ensures a user can only have one entry per challenge

    def __str__(self):
        return f"{self.user_profile.user.username} - {self.correct_submissions} correct submissions for {self.challenge.title}"

    def update_leaderboard(self):
        # Get or create the leaderboard entry
        leaderboard_entry, created = ChallengeLeaderboard.objects.get_or_create(
            challenge=self.challenge,
            user_profile=self.user_profile,
        )
        
        if created:
            # If this is a new entry, set correct submissions to 1
            leaderboard_entry.correct_submissions = 1
        else:
            # If the entry already exists, increment the correct submissions count
            leaderboard_entry.correct_submissions += 1
            
        leaderboard_entry.save()


class UserProfile(models.Model):
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('professor', 'Professor'),
        ('student', 'Student'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='student')
    verified = models.BooleanField(default=False)
    must_change_password = models.BooleanField(default=False)
    verification_code = models.CharField(max_length=6, blank=True, null=True)
    verification_code_sent_at = models.DateTimeField(blank=True, null=True)
    points = models.IntegerField(default=0)
    completed_challenges = models.ManyToManyField('Challenge', blank=True)
    correct_submissions = models.IntegerField(default=0)
    failed_submissions = models.IntegerField(default=0)
    last_analysis_update = models.DateTimeField(null=True, blank=True)
    last_correct_submissions = models.IntegerField(default=0)
    last_analysis = models.TextField(null=True, blank=True)
    last_failed_submissions = models.IntegerField(default=0)
    alias = models.CharField(max_length=30, blank=True, null=True)
    read_lessons = models.ManyToManyField('Lesson', blank=True, related_name='students_who_read')
    last_suggested_lesson = models.ForeignKey(
        'Lesson', null=True, blank=True, on_delete=models.SET_NULL, related_name='suggested_to_students')
    cybersecurity_trends = models.TextField(null=True, blank=True)
    section = models.CharField(max_length=10, blank=True, null=True)  # Add section field
    profile_picture = models.ImageField(upload_to='profile_pictures/', null=True, blank=True)  # Add this line

    def __str__(self):
        return f"{self.user.username} ({self.get_role_display()})"

    def calculate_success_rate(self):
        total_attempts = self.correct_submissions + self.failed_submissions
        if total_attempts == 0:
            return 0
        return (self.correct_submissions / total_attempts) * 100

    def update_submission_counts(self, is_correct, challenge=None):
        Submission.objects.create(user_profile=self, challenge=challenge, is_correct=is_correct)

        # Log the submission action
        action = 'challenge_submission' if is_correct else 'failed_submission'
        description = f"User {'correctly' if is_correct else 'incorrectly'} submitted challenge {challenge.name}"
        ActivityLog.objects.create(user=self.user, action=action, description=description)

        # Update the correct/incorrect submission counts
        if is_correct:
            self.correct_submissions += 1
        else:
            self.failed_submissions += 1

        if challenge and not is_correct:
            FailedSubmission.objects.create(user_profile=self, challenge=challenge)

        self.last_correct_submissions = self.correct_submissions
        self.last_failed_submissions = self.failed_submissions
        self.last_analysis_update = timezone.now()
        self.save()

    def generate_verification_code(self):
        self.verification_code = str(uuid.uuid4().int)[:6]
        self.verification_code_sent_at = timezone.now()
        self.save()
    

class ChatInteraction(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    user_message = models.TextField()
    bot_response = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)    
    def __str__(self):
        return f"Interaction by {self.user.username} at {self.timestamp}"
    

class Notification(models.Model):
    user = models.ForeignKey(User, related_name='notifications_received', on_delete=models.CASCADE)
    sender = models.ForeignKey(User, related_name='notifications_sent', on_delete=models.CASCADE)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    def __str__(self):
        return f'Notification to {self.user.username} from {self.sender.username}'

class DashboardConfig(models.Model):
    show_leaderboards = models.BooleanField(default=True)
    show_team_scores = models.BooleanField(default=True)
    show_report_and_stats = models.BooleanField(default=True)
    show_submission_overview_chart = models.BooleanField(default=True)
    
    # Add a logo field to store the uploaded logo image
    logo = models.ImageField(upload_to='logos/', null=True, blank=True)

    def __str__(self):
        return "Dashboard Configuration"
    

class ActivityLog(models.Model):
    ACTION_CHOICES = [
        ('login', 'Login'),
        ('logout', 'Logout'),
        ('challenge_submission', 'Challenge Submission'),
        ('failed_submission', 'Failed Submission'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)
    description = models.TextField(null=True, blank=True)  # Optional description for more detail

    def __str__(self):
        return f"{self.user.username} - {self.action} at {self.timestamp}"
    