"""Console de configuration de SentiMail V3.

Servie derrière Tailscale, sans compte utilisateur : l'accès au réseau *est*
l'autorisation. Il ne reste donc qu'une garantie, l'attribution : toute
modification laisse une trace nominative dans ``audit_log`` avec l'adresse IP
de l'appelant, écrite dans la même transaction que la modification elle-même.
"""
