using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using AspNetCore.Identity.ArangoDbCore.Models;

namespace AspNetCore.Identity.ArangoDbCore.Extensions
{
    public static class ClaimsHolderExtensions
    {
        /// <summary>
        /// Creates a <see cref="Claim"/> object from a <see cref="MongoClaim"/>
        /// </summary>
        /// <param name="arangoClaim">A <see cref="MongoClaim"/>.</param>
        /// <returns> A <see cref="Claim"/>.</returns>
        public static Claim ToClaim(this ArangoClaim arangoClaim)
        {
            return new Claim(arangoClaim.Type, arangoClaim.Value, null, arangoClaim.Issuer);
        }

        /// <summary>
        /// Adds a claim to a claim holder, implementing <see cref="IClaimHolder"/>.
        /// </summary>
        /// <param name="claimHolder">The object holding claims.</param>
        /// <param name="claim">The claim you want to add.</param>
        /// <returns>Returns true if the claim was added.</returns>
        public static bool AddClaim(this IClaimHolder claimHolder, Claim claim)
        {
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            // prevent adding duplicate claims
            if (claimHolder.HasClaim(claim))
            {
                return false;
            }

            claimHolder.Claims.Add(claim.ToArangoClaim());
            return true;
        }

        /// <summary>
        /// Replaces a claim on a claim holder, implementing <see cref="IClaimHolder"/>.
        /// </summary>
        /// <param name="claimHolder">The object holding claims.</param>
        /// <param name="claim">The claim you want to replace.</param>
        /// <param name="newClaim">The new claim you want to set.</param>
        /// <returns>Returns true if the claim was replaced.</returns>
        public static bool ReplaceClaim(this IClaimHolder claimHolder, Claim claim, Claim newClaim)
        {
            var replaced = false;
            claimHolder.Claims.Where(uc => uc.Value == claim.Value && uc.Type == claim.Type).ToList()
                .ForEach(oldClaim => {
                    oldClaim.Type = newClaim.Type;
                    oldClaim.Value = newClaim.Value;
                    oldClaim.Issuer = newClaim.Issuer;
                    replaced = true;
                });
            return replaced;
        }

        /// <summary>
        /// Removes a <see cref="Claim"/> from the <see cref="IClaimHolder"/>.
        /// </summary>
        /// <param name="claimHolder">The holder of the claim.</param>
        /// <param name="claim">The <see cref="Claim"/> to remove.</param>
        /// <returns>True is the claim was successfully removed.</returns>
        public static bool RemoveClaim(this IClaimHolder claimHolder, Claim claim)
        {
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }
            var exists = claimHolder.Claims
                .FirstOrDefault(e => e.Value == claim.Value
                                     && e.Type == claim.Type);
            if (exists == null) return false;
            claimHolder.Claims.Remove(exists);
            return true;
        }

        /// <summary>
        /// Removes an IEnumerable of <see cref="Claim"/>s from the <see cref="IClaimHolder"/>.
        /// </summary>
        /// <param name="claimHolder">The holder of the claims.</param>
        /// <param name="claims">The <see cref="Claim"/>s to remove.</param>
        /// <returns>True is the claims were successfully removed.</returns>
        public static bool RemoveClaims(this IClaimHolder claimHolder, IEnumerable<Claim> claims)
        {
            var someClaimsRemoved = false;
            foreach (var claim in claims)
            {
                var matchedClaims = claimHolder.Claims.Where(uc => uc.Value == claim.Value && uc.Type == claim.Type)
                    .ToList();

                foreach (var c in matchedClaims)
                {
                    claimHolder.Claims.Remove(c);
                    someClaimsRemoved = true;
                }
            }
            return someClaimsRemoved;
        }

        /// <summary>
        /// Creates a <see cref="MongoClaim"/> object from a <see cref="Claim"/>
        /// </summary>
        /// <param name="claim">The <see cref="Claim"/>.</param>
        /// <returns>A <see cref="MongoClaim"/>.</returns>
        public static ArangoClaim ToArangoClaim(this Claim claim)
        {
            return new ArangoClaim
            {
                Type = claim.Type,
                Value = claim.Value,
                Issuer = claim.Issuer
            };
        }

        /// <summary>
        /// Checks if an object implementing <see cref="IClaimHolder"/> has a claim.
        /// </summary>
        /// <param name="claimHolder">The object holding claims.</param>
        /// <param name="claim">The claim you want to replace.</param>
        /// <returns>Returns true if the claim is present, false otherwise.</returns>
        public static bool HasClaim(this IClaimHolder claimHolder, Claim claim)
        {
            if(claimHolder.Claims == null)
            {
                claimHolder.Claims = new List<ArangoClaim>();
            }
            return claimHolder.Claims.Any(e => e.Value == claim.Value && e.Type == claim.Type);
        }

    }
}
